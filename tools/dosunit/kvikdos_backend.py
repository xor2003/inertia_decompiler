"""Layer: DOS execution backend.

Responsibility: build isolated DOS harnesses and execute them through Kvikdos
without changing dosunit observation or comparison semantics.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.dosunit.model import DosUnitError, normalize_hex, parse_int

PSP_PARA = 0x100
IMAGE_PARA = PSP_PARA + 0x10
DOS_MEM_LIMIT = 0xA0000
ORIGINAL_IMAGE_PARA = 0x0100
MIRROR_CODE_PARA = 0x3000
AUTO_STACK_SEGMENT = 0x8000
HARNESS_CAPTURE_OFFSET = 0x0400
MIRROR_CAPTURE_OFFSET = 0xFE00
OBS_MAGIC = b"DUT1"
OBS_CAPTURED_OFFSET = 4
OBS_FIELDS_OFFSET = 6
OBS_FIELDS = ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "flags", "cs", "ds", "es", "ss")
OBS_SIZE = OBS_FIELDS_OFFSET + len(OBS_FIELDS) * 2
CAPTURE_STUB_RESERVE = 0x80 + OBS_SIZE


@dataclass(frozen=True)
class MzImage:
    """Parsed MZ image and relocation records used by a harness."""

    image: bytes
    relocs: tuple[tuple[int, int], ...]
    minalloc: int
    maxalloc: int


@dataclass(frozen=True)
class Harness:
    """Executable image plus the linear address of captured observations."""

    exe_bytes: bytes
    observation_linear: int


class KvikdosBackendError(DosUnitError):
    """Raised when the Kvikdos execution backend cannot complete a request."""



class KvikdosSession:
    """Own one reusable in-process Kvikdos VM and its temporary harness files."""

    def __init__(self, *, kvikdos_path: Path | None = None) -> None:
        """Create an inactive session; enter the context to allocate the VM."""
        self.kvikdos_path = kvikdos_path
        self._lib: ctypes.CDLL | None = None
        self._vm: ctypes.c_void_p | None = None
        self._tmp: tempfile.TemporaryDirectory[str] | None = None
        self._counter = 0

    def __enter__(self) -> KvikdosSession:
        """Allocate the native VM and return this active session."""
        self._lib = _load_libkvikdos()
        create = self._lib.dosvm_create
        create.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        create.restype = ctypes.c_int
        vm = ctypes.c_void_p()
        status = int(create(ctypes.byref(vm), None))
        if status != 0 or not vm.value:
            raise KvikdosBackendError(f"dosvm_create failed with status {status}")
        self._vm = vm
        self._tmp = tempfile.TemporaryDirectory(prefix="dosunit-session-")
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Destroy the native VM and remove session-local temporary files."""
        if self._lib is not None and self._vm is not None:
            destroy = self._lib.dosvm_destroy
            destroy.argtypes = [ctypes.c_void_p]
            destroy.restype = None
            destroy(self._vm)
        if self._tmp is not None:
            self._tmp.cleanup()
        self._lib = None
        self._vm = None
        self._tmp = None

    def run_harness(self, exe_bytes: bytes) -> bytes:
        """Run an executable harness and return its captured memory dump."""
        if self._lib is None or self._vm is None or self._tmp is None:
            raise KvikdosBackendError("KvikdosSession is not active")
        tmp_path = Path(self._tmp.name)
        self._counter += 1
        harness_path = tmp_path / f"harness-{self._counter:06d}.exe"
        dump_path = tmp_path / f"mem-{self._counter:06d}.dmp"
        harness_path.write_bytes(exe_bytes)
        run_program = self._lib.dosvm_run_program
        run_program.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        run_program.restype = ctypes.c_int
        status = int(run_program(self._vm, os.fsencode(harness_path), os.fsencode(dump_path)))
        if status != 0:
            raise KvikdosBackendError(f"dosvm_run_program failed with status {status}")
        if not dump_path.exists():
            raise KvikdosBackendError("kvikdos did not produce a memory dump")
        return dump_path.read_bytes()

    def snapshot_create(self) -> int:
        """Create and return a native VM snapshot handle."""
        if self._lib is None or self._vm is None:
            raise KvikdosBackendError("KvikdosSession is not active")
        create = self._lib.dosvm_snapshot_create
        create.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        create.restype = ctypes.c_int
        snapshot = ctypes.c_void_p()
        status = int(create(self._vm, ctypes.byref(snapshot)))
        if status != 0 or not snapshot.value:
            raise KvikdosBackendError(f"dosvm_snapshot_create failed with status {status}")
        return int(snapshot.value)

    def snapshot_restore(self, snapshot: int) -> None:
        """Restore a previously created native VM snapshot."""
        if self._lib is None or self._vm is None:
            raise KvikdosBackendError("KvikdosSession is not active")
        restore = self._lib.dosvm_snapshot_restore
        restore.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        restore.restype = ctypes.c_int
        status = int(restore(self._vm, ctypes.c_void_p(snapshot)))
        if status != 0:
            raise KvikdosBackendError(f"dosvm_snapshot_restore failed with status {status}")

    def snapshot_destroy(self, snapshot: int) -> None:
        """Release a native VM snapshot handle."""
        if self._lib is None:
            raise KvikdosBackendError("KvikdosSession is not active")
        destroy = self._lib.dosvm_snapshot_destroy
        destroy.argtypes = [ctypes.c_void_p]
        destroy.restype = None
        destroy(ctypes.c_void_p(snapshot))

    def read_memory(self, linear: int, size: int) -> bytes:
        """Read a byte range from the active guest memory image."""
        if self._lib is None or self._vm is None:
            raise KvikdosBackendError("KvikdosSession is not active")
        out = (ctypes.c_ubyte * size)()
        read = self._lib.dosvm_read_memory
        read.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t]
        read.restype = ctypes.c_int
        status = int(read(self._vm, linear, out, size))
        if status != 0:
            raise KvikdosBackendError(f"dosvm_read_memory failed with status {status}")
        return bytes(out)

    def write_memory(self, linear: int, data: bytes) -> None:
        """Write bytes into the active guest memory image."""
        if self._lib is None or self._vm is None:
            raise KvikdosBackendError("KvikdosSession is not active")
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        write = self._lib.dosvm_write_memory
        write.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t]
        write.restype = ctypes.c_int
        status = int(write(self._vm, linear, buf, len(data)))
        if status != 0:
            raise KvikdosBackendError(f"dosvm_write_memory failed with status {status}")


def execute_vector(
    vector: dict[str, Any],
    *,
    exe_path: Path,
    functions_catalog: dict[str, Any] | None = None,
    backend: str = "libkvikdos",
    kvikdos_path: Path | None = None,
    session: KvikdosSession | None = None,
) -> dict[str, Any]:
    """Execute one vector and return its normalized register observation."""
    normalized_backend = backend.lower()
    harness = build_harness(vector, exe_path=exe_path, functions_catalog=functions_catalog)
    if normalized_backend == "libkvikdos" and session is not None:
        dump = session.run_harness(harness.exe_bytes)
        return _observation_from_dump(vector, dump, harness.observation_linear)
    with tempfile.TemporaryDirectory(prefix="dosunit-") as tmp:
        tmp_path = Path(tmp)
        harness_path = tmp_path / "harness.exe"
        dump_path = tmp_path / "mem.dmp"
        harness_path.write_bytes(harness.exe_bytes)
        if normalized_backend == "libkvikdos":
            rc = _run_with_libkvikdos(harness_path, dump_path)
        elif normalized_backend == "kvikdos":
            rc = _run_with_kvikdos_cli(harness_path, dump_path, kvikdos_path=kvikdos_path)
        else:
            raise KvikdosBackendError(f"unsupported kvikdos backend: {backend}")
        if rc != 0:
            raise KvikdosBackendError(f"kvikdos harness exited with status {rc}")
        if not dump_path.exists():
            raise KvikdosBackendError("kvikdos did not produce a memory dump")
        dump = dump_path.read_bytes()
    return _observation_from_dump(vector, dump, harness.observation_linear)


def build_harness(
    vector: dict[str, Any],
    *,
    exe_path: Path,
    functions_catalog: dict[str, Any] | None = None,
) -> Harness:
    """Build a DOS harness that invokes the vector's selected function."""
    original = _read_mz(exe_path)
    _function, entry, return_kind = _vector_function_entry(vector)

    function_cs_para = _entry_segment_para(entry)
    function_ip = parse_int(entry.get("ip", entry.get("offset", "0x0000")), field="function.entry.ip") & 0xFFFF
    runtime_target_cs = IMAGE_PARA + ORIGINAL_IMAGE_PARA + function_cs_para
    runtime_harness_cs = IMAGE_PARA

    regs, ds, es, ss = _vector_pre_state(vector, entry, functions_catalog)

    image, relocs = _embed_shifted_image(original)

    capture_offset, capture_cs_para, return_ip, return_cs, capture_runtime_cs, runtime_target_cs = _resolve_capture_layout(
        original,
        image,
        function_cs_para=function_cs_para,
        return_kind=return_kind,
        runtime_harness_cs=runtime_harness_cs,
        runtime_target_cs=runtime_target_cs,
    )

    capture_stub = _capture_stub(capture_offset)
    _put_bytes(image, (capture_cs_para << 4) + capture_offset, capture_stub)
    obs_offset = capture_offset + len(capture_stub)
    _put_bytes(image, (capture_cs_para << 4) + obs_offset, _blank_observation())

    start = _start_stub(
        regs=regs,
        ds=ds,
        es=es,
        ss=ss,
        target_cs=runtime_target_cs,
        target_ip=function_ip,
        return_ip=return_ip,
        return_cs=return_cs,
    )
    _put_bytes(image, 0, start)
    _apply_static_memory(
        image,
        vector,
        segments={
            "CS": runtime_target_cs,
            "DS": ds,
            "ES": es,
            "SS": ss,
            "FS": 0,
            "GS": 0,
        },
    )

    exe_bytes = _make_mz(bytes(image), relocs=tuple(relocs), minalloc=max(0x1000, original.minalloc), maxalloc=0xFFFF)
    return Harness(exe_bytes=exe_bytes, observation_linear=(capture_runtime_cs << 4) + obs_offset)


def _vector_function_entry(vector: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Validate vector.function/vector.function.entry and return them plus return kind."""
    function = vector.get("function", {})
    if not isinstance(function, dict):
        raise KvikdosBackendError("vector.function must be an object")
    entry = function.get("entry", {})
    if not isinstance(entry, dict):
        raise KvikdosBackendError("vector.function.entry must be an object")
    return_kind = str(entry.get("kind") or function.get("return_kind") or "near").lower()
    if return_kind not in {"near", "far"}:
        raise KvikdosBackendError(f"unsupported return kind: {return_kind}")
    return function, entry, return_kind


def _vector_pre_state(
    vector: dict[str, Any],
    entry: dict[str, Any],
    functions_catalog: dict[str, Any] | None,
) -> tuple[dict[str, int], int, int, int]:
    """Resolve pre-state registers and segment registers; return (regs, ds, es, ss)."""
    pre = vector.get("pre", {})
    if not isinstance(pre, dict):
        raise KvikdosBackendError("vector.pre must be an object")
    regs: dict[str, int] = dict.fromkeys(("ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "flags"), 0)
    raw_regs = pre.get("regs", {})
    if isinstance(raw_regs, dict):
        for name in tuple(regs):
            if name in raw_regs:
                regs[name] = parse_int(raw_regs[name], field=f"pre.regs.{name}") & 0xFFFF
    if regs["sp"] == 0:
        raise KvikdosBackendError("pre.regs.sp must be non-zero so the return trap can be installed")

    data_segment_para = _default_data_segment_para(functions_catalog)
    raw_sregs = pre.get("sregs", {})
    if not isinstance(raw_sregs, dict):
        raw_sregs = {}
    ds = _resolve_segment(raw_sregs.get("ds", "auto"), default=IMAGE_PARA + ORIGINAL_IMAGE_PARA + data_segment_para)
    es = _resolve_segment(raw_sregs.get("es", "auto"), default=ds)
    ss = _resolve_segment(raw_sregs.get("ss", "auto"), default=AUTO_STACK_SEGMENT)
    if raw_sregs.get("cs") not in (None, "auto", entry.get("cs")):
        # The backend controls CS through function.entry so candidate mapping stays explicit.
        raise KvikdosBackendError("pre.sregs.cs must be auto or match function.entry.cs")
    return regs, ds, es, ss


def _embed_shifted_image(original: MzImage) -> tuple[bytearray, list[tuple[int, int]]]:
    """Embed the original image at ORIGINAL_IMAGE_PARA and shift relocations."""
    image = bytearray(ORIGINAL_IMAGE_PARA * 16 + len(original.image))
    image[ORIGINAL_IMAGE_PARA * 16 : ORIGINAL_IMAGE_PARA * 16 + len(original.image)] = original.image

    relocs: list[tuple[int, int]] = []
    for off, seg in original.relocs:
        shifted_seg = ORIGINAL_IMAGE_PARA + seg
        target = (shifted_seg << 4) + off
        if target + 2 > len(image):
            raise KvikdosBackendError(f"relocation outside embedded image: {seg:04x}:{off:04x}")
        current = int.from_bytes(image[target : target + 2], "little")
        image[target : target + 2] = ((current + ORIGINAL_IMAGE_PARA) & 0xFFFF).to_bytes(2, "little")
        relocs.append((off, shifted_seg))
    return image, relocs


def _resolve_capture_layout(
    original: MzImage,
    image: bytearray,
    *,
    function_cs_para: int,
    return_kind: str,
    runtime_harness_cs: int,
    runtime_target_cs: int,
) -> tuple[int, int, int, int | None, int, int]:
    """Resolve capture placement; return (capture_offset, capture_cs_para, return_ip, return_cs, capture_runtime_cs, runtime_target_cs)."""
    if return_kind == "near":
        capture_offset = _find_near_capture_offset(original.image, function_cs_para)
        if capture_offset is None:
            _install_mirror_code_segment(image, original_cs_para=ORIGINAL_IMAGE_PARA + function_cs_para)
            capture_cs_para = MIRROR_CODE_PARA
            return MIRROR_CAPTURE_OFFSET, capture_cs_para, MIRROR_CAPTURE_OFFSET, None, IMAGE_PARA + capture_cs_para, IMAGE_PARA + capture_cs_para
        capture_cs_para = ORIGINAL_IMAGE_PARA + function_cs_para
        return capture_offset, capture_cs_para, capture_offset, None, IMAGE_PARA + capture_cs_para, runtime_target_cs
    return HARNESS_CAPTURE_OFFSET, 0, HARNESS_CAPTURE_OFFSET, runtime_harness_cs, runtime_harness_cs, runtime_target_cs




def _read_mz(path: Path) -> MzImage:
    data = path.read_bytes()
    if len(data) < 0x1C or data[:2] not in {b"MZ", b"ZM"}:
        raise KvikdosBackendError("libkvikdos backend currently requires a DOS MZ .exe")
    lastsize = int.from_bytes(data[0x02:0x04], "little")
    nblocks = int.from_bytes(data[0x04:0x06], "little") & 0x7FF
    nreloc = int.from_bytes(data[0x06:0x08], "little")
    hdr_paras = int.from_bytes(data[0x08:0x0A], "little")
    minalloc = int.from_bytes(data[0x0A:0x0C], "little")
    maxalloc = int.from_bytes(data[0x0C:0x0E], "little")
    reloc_pos = int.from_bytes(data[0x18:0x1A], "little")
    exe_size = ((nblocks - 1) << 9) + lastsize if lastsize else nblocks << 9
    header_size = hdr_paras << 4
    if exe_size <= header_size or exe_size > len(data):
        raise KvikdosBackendError(f"bad MZ image/header size in {path}")
    relocs: list[tuple[int, int]] = []
    for idx in range(nreloc):
        at = reloc_pos + idx * 4
        if at + 4 > len(data):
            raise KvikdosBackendError(f"truncated MZ relocation table in {path}")
        off = int.from_bytes(data[at : at + 2], "little")
        seg = int.from_bytes(data[at + 2 : at + 4], "little")
        relocs.append((off, seg))
    return MzImage(image=data[header_size:exe_size], relocs=tuple(relocs), minalloc=minalloc, maxalloc=maxalloc)


def _make_mz(image: bytes, *, relocs: tuple[tuple[int, int], ...], minalloc: int, maxalloc: int) -> bytes:
    reloc_pos = 0x1C
    header_size = ((reloc_pos + len(relocs) * 4 + 15) // 16) * 16
    file_size = header_size + len(image)
    blocks, lastsize = divmod(file_size, 512)
    if lastsize:
        blocks += 1
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = blocks.to_bytes(2, "little")
    header[0x06:0x08] = len(relocs).to_bytes(2, "little")
    header[0x08:0x0A] = (header_size // 16).to_bytes(2, "little")
    header[0x0A:0x0C] = (minalloc & 0xFFFF).to_bytes(2, "little")
    header[0x0C:0x0E] = (maxalloc & 0xFFFF).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0080).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    header[0x14:0x16] = (0).to_bytes(2, "little")
    header[0x16:0x18] = (0).to_bytes(2, "little")
    header[0x18:0x1A] = reloc_pos.to_bytes(2, "little")
    for idx, (off, seg) in enumerate(relocs):
        at = reloc_pos + idx * 4
        header[at : at + 2] = (off & 0xFFFF).to_bytes(2, "little")
        header[at + 2 : at + 4] = (seg & 0xFFFF).to_bytes(2, "little")
    return bytes(header) + image


def _entry_segment_para(entry: dict[str, Any]) -> int:
    raw = entry.get("cs", entry.get("segment_para"))
    if raw is None or raw == "auto":
        raise KvikdosBackendError("function.entry.cs must be concrete for kvikdos execution")
    return parse_int(raw, field="function.entry.cs") & 0xFFFF


def _default_data_segment_para(functions_catalog: dict[str, Any] | None) -> int:
    if not isinstance(functions_catalog, dict):
        return 0
    for segment in functions_catalog.get("segments", []) or []:
        if not isinstance(segment, dict):
            continue
        if str(segment.get("name", "")).upper() == "DGROUP" and "paragraph" in segment:
            return parse_int(segment["paragraph"], field="segments[].paragraph") & 0xFFFF
    for segment in functions_catalog.get("segments", []) or []:
        if not isinstance(segment, dict):
            continue
        if str(segment.get("class", "")).upper() == "DATA" and "paragraph" in segment:
            return parse_int(segment["paragraph"], field="segments[].paragraph") & 0xFFFF
    return 0


def _resolve_segment(raw: object, *, default: int) -> int:
    if raw is None:
        return default & 0xFFFF
    if isinstance(raw, str) and raw.strip().lower() == "auto":
        return default & 0xFFFF
    return parse_int(raw, field="segment") & 0xFFFF


def _find_near_capture_offset(original_image: bytes, function_cs_para: int) -> int | None:
    needed = CAPTURE_STUB_RESERVE
    base = function_cs_para << 4
    max_offset = 0x10000 - needed
    if base >= len(original_image):
        return 0x0100
    image_window_end = min(len(original_image) - base, 0x10000)
    if image_window_end <= max_offset:
        return max(0x0100, image_window_end)
    haystack = original_image[base : base + image_window_end]
    for fill in (0x00, 0xCC, 0x90):
        run = bytes([fill]) * needed
        found = haystack.find(run, 0x0100)
        if 0 <= found <= max_offset:
            return found
    return None


def _install_mirror_code_segment(image: bytearray, *, original_cs_para: int) -> None:
    source = original_cs_para << 4
    if source >= len(image):
        raise KvikdosBackendError("cannot mirror code segment outside embedded image")
    segment = bytes(image[source : min(len(image), source + 0x10000)]).ljust(0x10000, b"\x00")
    target = MIRROR_CODE_PARA << 4
    _put_bytes(image, target, segment)


def _put_bytes(image: bytearray, offset: int, data: bytes) -> None:
    if offset < 0:
        raise KvikdosBackendError("negative harness image offset")
    end = offset + len(data)
    if end > len(image):
        image.extend(b"\x00" * (end - len(image)))
    image[offset:end] = data


def _blank_observation() -> bytes:
    data = bytearray(OBS_SIZE)
    data[0:4] = OBS_MAGIC
    return bytes(data)


def _capture_stub(capture_offset: int) -> bytes:
    obs = capture_offset + 0x80
    code = bytearray()

    def store_reg(reg_code: int, field: str) -> None:
        off = obs + OBS_FIELDS_OFFSET + OBS_FIELDS.index(field) * 2
        code.extend(b"\x2e\x89")
        code.append(0x06 | (reg_code << 3))
        code.extend(_u16(off))

    def store_ax(field: str) -> None:
        off = obs + OBS_FIELDS_OFFSET + OBS_FIELDS.index(field) * 2
        code.extend(b"\x2e\xa3")
        code.extend(_u16(off))

    store_reg(4, "sp")
    store_reg(0, "ax")
    code.extend(b"\x9c\x58")
    store_ax("flags")
    store_reg(3, "bx")
    store_reg(1, "cx")
    store_reg(2, "dx")
    store_reg(6, "si")
    store_reg(7, "di")
    store_reg(5, "bp")
    for field, opcode in (("cs", b"\x8c\xc8"), ("ds", b"\x8c\xd8"), ("es", b"\x8c\xc0"), ("ss", b"\x8c\xd0")):
        code.extend(opcode)
        store_ax(field)
    code.extend(b"\xb8\x01\x00\x2e\xa3")
    code.extend(_u16(obs + OBS_CAPTURED_OFFSET))
    code.extend(b"\xb8\x00\x4c\xcd\x21")
    if len(code) > 0x80:
        raise KvikdosBackendError("capture stub is larger than reserved observation gap")
    return bytes(code).ljust(0x80, b"\x90")


def _start_stub(
    *,
    regs: dict[str, int],
    ds: int,
    es: int,
    ss: int,
    target_cs: int,
    target_ip: int,
    return_ip: int,
    return_cs: int | None,
) -> bytes:
    sp = regs["sp"]
    code = bytearray()
    code.extend(_mov_r16_imm("ax", ss))
    code.extend(b"\x8e\xd8")  # mov ds, ax
    code.extend(_mov_moffs_imm16(sp, return_ip))
    if return_cs is not None:
        code.extend(_mov_moffs_imm16((sp + 2) & 0xFFFF, return_cs))
    code.extend(_mov_r16_imm("ax", ds))
    code.extend(b"\x8e\xd8")  # mov ds, ax
    code.extend(_mov_r16_imm("ax", es))
    code.extend(b"\x8e\xc0")  # mov es, ax
    code.extend(_mov_r16_imm("ax", ss))
    code.extend(b"\x8e\xd0")  # mov ss, ax
    code.extend(_mov_r16_imm("sp", sp))
    for reg in ("bx", "cx", "dx", "si", "di", "bp"):
        code.extend(_mov_r16_imm(reg, regs[reg]))
    code.extend(_mov_r16_imm("ax", regs["flags"] | 0x0002))
    code.extend(b"\x50\x9d")  # push ax; popf
    code.extend(_mov_r16_imm("ax", regs["ax"]))
    code.extend(_push_imm16(target_cs))
    code.extend(_push_imm16(target_ip))
    code.extend(b"\xcb")  # retf
    return bytes(code)


def _apply_static_memory(image: bytearray, vector: dict[str, Any], *, segments: dict[str, int]) -> None:
    pre = vector.get("pre", {})
    if not isinstance(pre, dict):
        return
    for idx, item in enumerate(pre.get("memory", []) or []):
        if not isinstance(item, dict):
            raise KvikdosBackendError(f"pre.memory[{idx}] must be an object")
        data = bytes.fromhex(str(item.get("bytes", "")))
        linear = _memory_item_linear(item, segments=segments, field=f"pre.memory[{idx}]")
        image_offset = linear - (IMAGE_PARA << 4)
        if image_offset < 0:
            raise KvikdosBackendError(f"pre.memory[{idx}] writes below generated image")
        _put_bytes(image, image_offset, data)


def _observation_from_dump(vector: dict[str, Any], dump: bytes, observation_linear: int) -> dict[str, Any]:
    if observation_linear + OBS_SIZE > len(dump):
        raise KvikdosBackendError("observation block is outside kvikdos dump")
    block = dump[observation_linear : observation_linear + OBS_SIZE]
    if block[0:4] != OBS_MAGIC:
        raise KvikdosBackendError("observation block magic mismatch")
    captured = int.from_bytes(block[OBS_CAPTURED_OFFSET : OBS_CAPTURED_OFFSET + 2], "little")
    if captured != 1:
        raise KvikdosBackendError("target function did not return through the dosunit capture trap")
    values = {
        field: int.from_bytes(
            block[OBS_FIELDS_OFFSET + idx * 2 : OBS_FIELDS_OFFSET + idx * 2 + 2],
            "little",
        )
        for idx, field in enumerate(OBS_FIELDS)
    }
    observe = vector.get("observe", {})
    if not isinstance(observe, dict):
        observe = {}
    regs = {reg: normalize_hex(values[reg], width=4) for reg in observe.get("regs", []) or [] if reg in values}
    sregs = {reg: normalize_hex(values[reg], width=4) for reg in observe.get("sregs", []) or [] if reg in values}
    mask = parse_int(observe.get("flags_mask", "0xffff"), field="observe.flags_mask") & 0xFFFF
    memory = _observed_memory(
        observe.get("memory", []) or [],
        dump,
        segments={
            "CS": values["cs"],
            "DS": values["ds"],
            "ES": values["es"],
            "SS": values["ss"],
            "FS": 0,
            "GS": 0,
        },
    )
    return {
        "status": "returned",
        "regs": regs,
        "sregs": sregs,
        "flags": {"value": normalize_hex(values["flags"] & mask, width=4), "mask": normalize_hex(mask, width=4)},
        "memory": memory,
        "return": {"kind": str(vector.get("function", {}).get("entry", {}).get("kind", "near"))},
        "calls": [],
    }


def _observed_memory(ranges: list[Any], dump: bytes, *, segments: dict[str, int]) -> list[dict[str, Any]]:
    observed: list[dict[str, Any]] = []
    for idx, item in enumerate(ranges):
        if not isinstance(item, dict):
            raise KvikdosBackendError(f"observe.memory[{idx}] must be an object")
        size = parse_int(item.get("size", item.get("length", 0)), field=f"observe.memory[{idx}].size")
        linear = _memory_item_linear(item, segments=segments, field=f"observe.memory[{idx}]")
        if linear + size > len(dump):
            raise KvikdosBackendError(f"observe.memory[{idx}] is outside kvikdos dump")
        observed.append({**item, "bytes": dump[linear : linear + size].hex()})
    return observed


def _memory_item_linear(item: dict[str, Any], *, segments: dict[str, int], field: str) -> int:
    space = str(item.get("space", "")).upper()
    if space == "LINEAR":
        return parse_int(item.get("linear"), field=f"{field}.linear")
    if space == "SEG":
        segment = parse_int(item.get("segment"), field=f"{field}.segment")
        offset = parse_int(item.get("offset"), field=f"{field}.offset")
        return ((segment & 0xFFFF) << 4) + (offset & 0xFFFF)
    if space in {"CS", "DS", "ES", "SS", "FS", "GS"}:
        if space not in segments:
            raise KvikdosBackendError(f"{field} cannot resolve {space}")
        offset = parse_int(item.get("offset"), field=f"{field}.offset")
        return ((segments[space] & 0xFFFF) << 4) + (offset & 0xFFFF)
    raise KvikdosBackendError(f"unsupported {field} space: {space}")


def _u16(value: int) -> bytes:
    return (value & 0xFFFF).to_bytes(2, "little")


def _mov_r16_imm(reg: str, value: int) -> bytes:
    codes = {"ax": 0, "cx": 1, "dx": 2, "bx": 3, "sp": 4, "bp": 5, "si": 6, "di": 7}
    return bytes([0xB8 + codes[reg]]) + _u16(value)


def _push_imm16(value: int) -> bytes:
    return b"\x68" + _u16(value)


def _mov_moffs_imm16(offset: int, value: int) -> bytes:
    return b"\xc7\x06" + _u16(offset) + _u16(value)


_LIB: ctypes.CDLL | None = None


def _run_with_libkvikdos(harness_path: Path, dump_path: Path) -> int:
    lib = _load_libkvikdos()
    func = lib.dosunit_kvikdos_run
    func.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    func.restype = ctypes.c_int
    return int(func(os.fsencode(harness_path), os.fsencode(dump_path)))


def _load_libkvikdos() -> ctypes.CDLL:
    global _LIB
    if _LIB is not None:
        return _LIB
    kvikdos_c = Path(os.environ.get("DOSUNIT_KVIKDOS_C", "/home/xor/kvikdos/kvikdos.c"))
    if not kvikdos_c.exists():
        raise KvikdosBackendError(f"kvikdos.c not found: {kvikdos_c}")
    cache = Path(os.environ.get("DOSUNIT_CACHE_DIR", ".cache/dosunit")).resolve()
    cache.mkdir(parents=True, exist_ok=True)
    wrapper = cache / "libkvikdos_wrapper.c"
    shared = cache / "libdosunit_kvikdos.so"
    source = f"""
#define main kvikdos_embedded_main
#include "{kvikdos_c}"
#undef main

typedef enum DosVmStatus {{
  DOSVM_STATUS_OK = 0,
  DOSVM_STATUS_TRAP = 1,
  DOSVM_STATUS_TIMEOUT = 2,
  DOSVM_STATUS_FAULT = 3,
  DOSVM_STATUS_UNSUPPORTED = 4,
  DOSVM_STATUS_BACKEND_ERROR = 5
}} DosVmStatus;

typedef struct DosVm {{
  EmuState emu;
}} DosVm;

typedef struct DosVmSnapshot {{
  unsigned char *mem;
  unsigned size;
}} DosVmSnapshot;

DosVmStatus dosvm_create(DosVm **out_vm, const void *config) {{
  DosVm *vm;
  (void)config;
  if (!out_vm) return DOSVM_STATUS_BACKEND_ERROR;
  vm = (DosVm*)calloc(1, sizeof(*vm));
  if (!vm) return DOSVM_STATUS_BACKEND_ERROR;
  init_emu(&vm->emu);
  *out_vm = vm;
  return DOSVM_STATUS_OK;
}}

void dosvm_destroy(DosVm *vm) {{
  if (!vm) return;
  free(vm);
}}

DosVmStatus dosvm_snapshot_create(DosVm *vm, DosVmSnapshot **out_snapshot) {{
  DosVmSnapshot *snapshot;
  if (!vm || !vm->emu.mem || !out_snapshot) return DOSVM_STATUS_BACKEND_ERROR;
  snapshot = (DosVmSnapshot*)calloc(1, sizeof(*snapshot));
  if (!snapshot) return DOSVM_STATUS_BACKEND_ERROR;
  snapshot->mem = (unsigned char*)malloc(DOS_MEM_LIMIT);
  if (!snapshot->mem) {{
    free(snapshot);
    return DOSVM_STATUS_BACKEND_ERROR;
  }}
  memcpy(snapshot->mem, vm->emu.mem, DOS_MEM_LIMIT);
  snapshot->size = DOS_MEM_LIMIT;
  *out_snapshot = snapshot;
  return DOSVM_STATUS_OK;
}}

DosVmStatus dosvm_snapshot_restore(DosVm *vm, const DosVmSnapshot *snapshot) {{
  if (!vm || !vm->emu.mem || !snapshot || !snapshot->mem || snapshot->size != DOS_MEM_LIMIT) return DOSVM_STATUS_BACKEND_ERROR;
  memcpy(vm->emu.mem, snapshot->mem, DOS_MEM_LIMIT);
  return DOSVM_STATUS_OK;
}}

void dosvm_snapshot_destroy(DosVmSnapshot *snapshot) {{
  if (!snapshot) return;
  free(snapshot->mem);
  free(snapshot);
}}

DosVmStatus dosvm_read_memory(DosVm *vm, unsigned linear, void *out_bytes, size_t size) {{
  if (!vm || !vm->emu.mem || !out_bytes || linear > DOS_MEM_LIMIT || size > DOS_MEM_LIMIT - linear) return DOSVM_STATUS_BACKEND_ERROR;
  memcpy(out_bytes, (const char*)vm->emu.mem + linear, size);
  return DOSVM_STATUS_OK;
}}

DosVmStatus dosvm_write_memory(DosVm *vm, unsigned linear, const void *bytes, size_t size) {{
  if (!vm || !vm->emu.mem || !bytes || linear > DOS_MEM_LIMIT || size > DOS_MEM_LIMIT - linear) return DOSVM_STATUS_BACKEND_ERROR;
  memcpy((char*)vm->emu.mem + linear, bytes, size);
  return DOSVM_STATUS_OK;
}}

DosVmStatus dosvm_run_program(DosVm *vm, const char *prog_filename, const char *dump_filename) {{
  ParsedCmdArgs cmd_args;
  TtyState tty_state;
  char placeholder[] = ".";
  const char *empty_args[] = {{ NULL }};
  int exit_code;
  if (!vm || !prog_filename) return DOSVM_STATUS_BACKEND_ERROR;
  init_parsed_cmd_args(&cmd_args, placeholder);
  init_tty_state(&tty_state, -3);
  cmd_args.prog_filename = prog_filename;
  cmd_args.emu_params.strict_mode = 0;
  cmd_args.emu_params.is_hlt_ok = 0;
  g_case_fallback_mode = 2;
  g_diag_file = stderr;
  if (dump_filename && dump_filename[0]) {{
    g_mem_dump_filename = (char*)dump_filename;
    g_mem_dump_start = 0;
    g_mem_dump_size = DOS_MEM_LIMIT;
  }} else {{
    g_mem_dump_filename = NULL;
    g_mem_dump_start = 0;
    g_mem_dump_size = 0;
  }}
  exit_code = run_dos_prog(&vm->emu, prog_filename, "", empty_args, &cmd_args.dir_state, &tty_state, &cmd_args.emu_params, NULL, NULL, 0);
  return exit_code == 0 ? DOSVM_STATUS_OK : DOSVM_STATUS_FAULT;
}}

int dosunit_kvikdos_run(const char *prog_filename, const char *dump_filename) {{
  DosVm *vm = NULL;
  DosVmStatus status = dosvm_create(&vm, NULL);
  if (status != DOSVM_STATUS_OK) return status;
  status = dosvm_run_program(vm, prog_filename, dump_filename);
  dosvm_destroy(vm);
  return status;
}}
"""
    if not wrapper.exists() or wrapper.read_text() != source:
        wrapper.write_text(source)
    cc = os.environ.get("CC", "cc")
    with tempfile.NamedTemporaryFile(prefix="libdosunit_kvikdos.", suffix=".tmp", dir=cache, delete=False) as handle:
        temporary_shared = Path(handle.name)
    try:
        result = subprocess.run(
            [cc, "-shared", "-fPIC", "-O2", "-w", "-o", str(temporary_shared), str(wrapper)],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise KvikdosBackendError(f"failed to build libkvikdos wrapper: {result.stderr.strip()}")
        os.replace(temporary_shared, shared)
    finally:
        temporary_shared.unlink(missing_ok=True)
    _LIB = ctypes.CDLL(str(shared))
    return _LIB


def _run_with_kvikdos_cli(harness_path: Path, dump_path: Path, *, kvikdos_path: Path | None) -> int:
    executable = kvikdos_path or Path(os.environ.get("DOSUNIT_KVIKDOS", "/home/xor/kvikdos/kvikdos"))
    found = shutil.which(str(executable)) if not executable.is_absolute() else str(executable)
    if not found or not Path(found).exists():
        raise KvikdosBackendError(f"kvikdos executable not found: {executable}")
    env = dict(os.environ)
    env["KVIKDOS_MEM_DUMP"] = str(dump_path)
    env["KVIKDOS_MEM_DUMP_START"] = "0"
    env["KVIKDOS_MEM_DUMP_SIZE"] = str(DOS_MEM_LIMIT)
    result = subprocess.run(
        [found, "--tty-in=-3", str(harness_path)],
        check=False,
        capture_output=True,
        env=env,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise KvikdosBackendError(f"kvikdos exited with status {result.returncode}: {stderr}")
    return result.returncode
