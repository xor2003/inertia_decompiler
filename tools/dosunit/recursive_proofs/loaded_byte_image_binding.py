"""Layer: dosunit executable initialization binding (staging).

Responsibility: derive immutable byte-relation inputs from the actual MZ or
PE32/ELF32 loader, retaining file/model/configuration identity. This binds loaded
bytes only; permissions, unspecified DOS allocation, imports and startup are
reported inputs, never a closed physical or environment proof.
"""
from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass
from enum import StrEnum
from importlib.metadata import version
from pathlib import Path

import angr

from tools.dosunit.architectures.flat32_pe_loader import InclusivePE
from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.contracts.proof_contracts import Architecture
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedBytes, LoadedRelationLimits, snapshot_loaded_bytes
from tools.dosunit.runtime.real16_mz_load import image_from_mz_bytes, parse_mz
from tools.dosunit.runtime.real16_replay_model import Real16Image

MAX_FILE_BYTES: int = 4 * 1024 * 1024
MAX_MAPPING_RECORDS: int = 65536


class ImageBindingReason(StrEnum):
    """Named admission failures without invented loader or execution evidence."""

    FORMAT = "loaded_binding_executable_format_refused"
    RESOURCE = "loaded_binding_intake_budget_exhausted"
    CHANGED = "loaded_binding_project_bytes_or_coordinates_changed"


class ImageBindingRefusal(Exception):
    """Retain an exact typed failure at this file/loader boundary."""

    def __init__(self, reason: ImageBindingReason, detail: str) -> None:
        """Expose both the missing evidence and its original diagnostic."""
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class LoadedMapping:
    """One loader-declared memory span and its actual permission metadata."""

    address: int
    size: int
    readable: bool
    writable: bool
    executable: bool


@dataclass(frozen=True, slots=True)
class LoadedImageBinding:
    """File-bound initialization evidence, distinct from scalar function proof."""

    snapshot: LoadedBytes
    file_sha256: str
    loader: str
    model_hash: str
    mapped_base: int
    linked_base: int
    entry: int
    mappings: tuple[LoadedMapping, ...]
    unspecified_allocation: tuple[tuple[int, int], ...] = ()
    relocation_sha256: str = ""
    entry_registers: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class BoundReal16Load:
    """The existing relocated replay image and its exact immutable byte binding."""

    binding: LoadedImageBinding
    image: Real16Image
    file_bytes: bytes

    def verify(self, *, limits: LoadedRelationLimits | None = None) -> None:
        """Rebuild the immutable relocation receipt from retained executable bytes."""
        current = bind_real16_mz(self.file_bytes, load_segment=self.image.load_segment, limits=limits)
        if current != self:
            raise ImageBindingRefusal(ImageBindingReason.CHANGED, "MZ load differs from its file/model receipt")


@dataclass(frozen=True, slots=True)
class BoundFlat32Load:
    """One actual third-party project paired with its immutable load receipt.

    The project remains mutable. Recheck the receipt before consumption and
    after lowering; keeping this wrapper alone does not freeze CLE state.
    """

    binding: LoadedImageBinding
    project: angr.Project
    file_bytes: bytes

    def verify(self, *, limits: LoadedRelationLimits | None = None) -> None:
        """Refuse changed backers, mappings or coordinates before native reuse."""
        selected = limits if limits is not None else LoadedRelationLimits()
        _intake(self.file_bytes, selected)
        current = _flat_binding(self.project, hashlib.sha256(self.file_bytes).hexdigest(), selected)
        if current != self.binding:
            raise ImageBindingRefusal(ImageBindingReason.CHANGED, "live CLE image differs from its load receipt")


def _intake(data: bytes, limits: LoadedRelationLimits) -> None:
    """Bound immutable executable intake before parser or loader allocation."""
    limits.check_time()
    if type(data) is not bytes or not data:
        raise ImageBindingRefusal(ImageBindingReason.FORMAT, "executable must be nonempty immutable bytes")
    if len(data) > MAX_FILE_BYTES:
        raise ImageBindingRefusal(ImageBindingReason.RESOURCE, "executable exceeds file intake allowance")


def _model_hash(architecture: Architecture) -> str:
    """Bind this factory, the authoritative MZ loader and installed CLE model."""
    from tools.dosunit.architectures import flat32_pe_loader
    from tools.dosunit.runtime import real16_mz_load

    paths = (Path(__file__), Path(real16_mz_load.__file__), Path(flat32_pe_loader.__file__))
    document = {"version": "loaded-executable-binding-v1", "architecture": architecture.value,
                "sources": [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths],
                "angr": version("angr"), "cle": version("cle"), "pyvex": version("pyvex")}
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def bind_real16_mz(data: bytes, *, load_segment: int,
                  limits: LoadedRelationLimits | None = None) -> BoundReal16Load:
    """Bind the exact existing MZ relocation result without guessing DOS BSS.

    Minimum allocation specifies reserved paragraphs, not initialized bytes.
    Retain that region as unspecified; never seed independent zero bytes there.
    No PSP, loader entry registers or DOS services are established here.
    """
    selected = limits if limits is not None else LoadedRelationLimits()
    _intake(data, selected)
    if type(load_segment) is not int or not 0 <= load_segment <= 0xFFFF:
        raise ImageBindingRefusal(ImageBindingReason.FORMAT, "load segment requires a 16-bit paragraph")
    header = parse_mz(data)
    if len(header.image) > selected.max_bytes:
        raise ImageBindingRefusal(ImageBindingReason.RESOURCE, "MZ initialized bytes exceed snapshot allowance")
    image = image_from_mz_bytes(data, load_segment=load_segment)
    selected.check_time()
    snapshot = snapshot_loaded_bytes(Architecture.REAL16, image.chunks, limits=selected)
    base = load_segment * 16
    allocation = ((base + image.image_size, image.bss_size),) if image.bss_size else ()
    binding = LoadedImageBinding(snapshot, image.file_sha256, "dosunit.real16_mz_load",
                                 _model_hash(Architecture.REAL16), base, 0,
                                 (((load_segment + header.entry_cs) & 0xFFFF) << 4) + header.entry_ip,
                                 (LoadedMapping(base, image.image_size, True, True, True),),
                                 allocation, image.reloc_sha256,
                                 (("cs", (load_segment + header.entry_cs) & 0xFFFF), ("ip", header.entry_ip),
                                  ("ss", (load_segment + header.stack_ss) & 0xFFFF), ("sp", header.stack_sp)))
    selected.check_time()
    return BoundReal16Load(binding, image, data)


def _flat_format(data: bytes) -> None:
    """Admit only little-endian i386 ELF32 or PE32 file headers."""
    if data[:4] == b"\x7fELF":
        valid = len(data) >= 52 and data[4:7] == b"\x01\x01\x01" and int.from_bytes(data[18:20], "little") == 3
    elif data[:2] == b"MZ" and len(data) >= 64:
        at = int.from_bytes(data[60:64], "little")
        valid = (at + 26 <= len(data) and data[at:at + 4] == b"PE\0\0"
                 and int.from_bytes(data[at + 4:at + 6], "little") == 0x14C
                 and int.from_bytes(data[at + 24:at + 26], "little") == 0x10B)
    else:
        valid = False
    if not valid:
        raise ImageBindingRefusal(ImageBindingReason.FORMAT, "expected i386 little-endian PE32 or ELF32")


def _flat_allocation(data: bytes, limits: LoadedRelationLimits) -> None:
    """Refuse oversized file-declared mappings before CLE allocates byte backers."""
    if data[:4] == b"\x7fELF":
        start = int.from_bytes(data[28:32], "little")
        stride = int.from_bytes(data[42:44], "little")
        count = int.from_bytes(data[44:46], "little")
        if stride < 32 or start + count * stride > len(data):
            raise ImageBindingRefusal(ImageBindingReason.FORMAT, "ELF program header table is incomplete")
        total = 0
        for index in range(count):
            limits.check_time()
            at = start + index * stride
            # TLS and other declared spans can allocate loader state as well.
            # Their budget cannot depend on whether they become PT_LOAD bytes.
            size = int.from_bytes(data[at + 20:at + 24], "little")
            total += size
            if total > limits.max_bytes:
                raise ImageBindingRefusal(ImageBindingReason.RESOURCE, "ELF declared mappings exceed byte allowance")
    else:
        _pe_allocation(data, limits)


def _pe_allocation(data: bytes, limits: LoadedRelationLimits) -> None:
    """Check actual section spans independently of the PE SizeOfImage claim."""
    at = int.from_bytes(data[60:64], "little") + 24
    optional_size = int.from_bytes(data[at - 4:at - 2], "little")
    if optional_size < 60 or at + optional_size > len(data):
        raise ImageBindingRefusal(ImageBindingReason.FORMAT, "PE optional header is incomplete")
    if int.from_bytes(data[at + 56:at + 60], "little") > limits.max_bytes:
        raise ImageBindingRefusal(ImageBindingReason.RESOURCE, "PE declared image exceeds byte allowance")
    start = at + optional_size
    count = int.from_bytes(data[at - 18:at - 16], "little")
    if start + count * 40 > len(data):
        raise ImageBindingRefusal(ImageBindingReason.FORMAT, "PE section table is incomplete")
    total = 0
    for index in range(count):
        limits.check_time()
        section = start + index * 40
        virtual_size = int.from_bytes(data[section + 8:section + 12], "little")
        virtual_address = int.from_bytes(data[section + 12:section + 16], "little")
        raw_size = int.from_bytes(data[section + 16:section + 20], "little")
        total += max(virtual_size, raw_size)
        span = virtual_address + max(virtual_size, raw_size)
        if total > limits.max_bytes or span > limits.max_bytes:
            raise ImageBindingRefusal(ImageBindingReason.RESOURCE, "PE section spans exceed byte allowance")


def _flat_binding(project: angr.Project, file_sha256: str,
                  limits: LoadedRelationLimits) -> LoadedImageBinding:
    """Capture complete actual CLE backers and bounded loader mapping metadata."""
    limits.check_time()
    if project.arch.name != "X86" or project.arch.bits != 32:
        raise ImageBindingRefusal(ImageBindingReason.FORMAT, "loader did not produce an i386 project")
    chunks: list[tuple[int, bytes]] = []
    total = 0
    for address, data in project.loader.memory.backers():
        limits.check_time()
        if len(chunks) >= MAX_MAPPING_RECORDS or len(data) > limits.max_bytes - total:
            raise ImageBindingRefusal(ImageBindingReason.RESOURCE, "CLE initialized bytes exceed snapshot allowance")
        total += len(data)
        chunks.append((int(address), bytes(data)))
    snapshot = snapshot_loaded_bytes(Architecture.FLAT32, tuple(chunks), limits=limits)
    mappings: list[LoadedMapping] = []
    for obj in project.loader.all_objects:
        # CLE PE objects expose section mappings rather than ELF segments.
        # Snapshot bytes alone cannot supply the omitted permission metadata.
        regions = obj.segments if obj.segments else obj.sections
        for segment in regions:
            limits.check_time()
            if len(mappings) >= MAX_MAPPING_RECORDS:
                raise ImageBindingRefusal(ImageBindingReason.RESOURCE, "CLE mappings exceed record allowance")
            mappings.append(LoadedMapping(int(segment.vaddr), int(segment.memsize),
                                          bool(segment.is_readable), bool(segment.is_writable),
                                          bool(segment.is_executable)))
    main = project.loader.main_object
    binding = LoadedImageBinding(snapshot, file_sha256, type(main).__qualname__, _model_hash(Architecture.FLAT32),
                                 int(main.mapped_base), int(main.linked_base), int(project.entry),
                                 tuple(sorted(mappings, key=lambda row: (row.address, row.size))))
    limits.check_time()
    return binding


def bind_flat32_file(data: bytes, *, mapped_base: int | None = None,
                     limits: LoadedRelationLimits | None = None) -> BoundFlat32Load:
    """Load immutable supported file bytes into the project native SSA will use.

    Library loading stays disabled as in the existing comparator. Extern/import
    backers remain in the snapshot; their initialized bytes grant no proof of
    imported behavior. Arbitrary custom loaders or shellcode are not accepted.
    """
    selected = limits if limits is not None else LoadedRelationLimits()
    _intake(data, selected)
    _flat_format(data)
    _flat_allocation(data, selected)
    if mapped_base is not None and (type(mapped_base) is not int or not 0 <= mapped_base < 2**32):
        raise ImageBindingRefusal(ImageBindingReason.FORMAT, "mapped base requires an i386 coordinate")
    options: dict[str, object] = {} if mapped_base is None else {"base_addr": mapped_base}
    if data[:2] == b"MZ":
        options.update(backend=InclusivePE, max_mapped_bytes=selected.max_bytes)
    project = angr.Project(io.BytesIO(data), auto_load_libs=False, main_opts=options)
    binding = _flat_binding(project, hashlib.sha256(data).hexdigest(), selected)
    return BoundFlat32Load(binding, project, data)
