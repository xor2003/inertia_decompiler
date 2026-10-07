"""Binary-derived initialized PE32 boot contract for independent whole-program replay.

Layer: dosunit concrete execution.
Responsibility: derive a PE32 program boot contract — the admitted main-image
loaded bytes, the loaded entry point, the file-declared permission regions and
the caller-declared initial register file and preinitialized data allocations —
from actual serialized PE32 bytes and a declared ``PeProgramEnvironment``.
This owner constructs boot state only: it writes no guest memory, installs no
caller frame, return trap or manufactured stack, and synthesizes no Windows
loader state (TEB/PEB, process parameters, TLS callbacks). The only optional
loader effect is the caller-declared import binding: declared service
addresses sealed into the loaded IAT under an explicit typed contract, never
a silent Windows claim. Every initial byte is either a loaded image byte or a
declared environment allocation; every register value is caller-declared,
never a default.

Admitted PE32 scope is deliberately narrow: a genuine i386 PE32 EXE whose
bound-import, delay-import, TLS, load-config and CLR directories are all
empty. Each such directory names initialization-time effects this contract
refuses to skip silently, and no CLE synthetic import stubs are bound into
the admitted image. By default the import and IAT directories are refused
too; a caller may opt in to a bounded declared import model by supplying
``PeProgramEnvironment.services`` — typed ``dll!name`` contracts that must
cover every admitted raw import exactly, and whose declared synthetic
service addresses are written into the sealed loaded IAT. This module does
not claim whole-program Windows emulation or the full M6 goal; it provides
only the distinct initialized program-boot slice, complementing (not
replacing) function-vector replay.
"""

from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import dataclass
from itertools import pairwise
from typing import Any, cast

import angr
import pefile
from cle.errors import CLEError

from tools.dosunit.architectures.flat32_pe_loader import InclusivePE
from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.runtime.flat32_memory_permissions import (
    MAX_MAPPED_BYTES,
    MAX_PAGE_CLAIMS,
    DeclaredAccess,
    DeclaredRegion,
    MappingOrigin,
)
from tools.dosunit.runtime.flat32_replay_memory import image_from_project
from tools.dosunit.runtime.flat32_replay_model import REGISTER_IDS, ReplayImage
from tools.dosunit.runtime.pe32_import_service import (
    MAX_IMPORT_BINDINGS,
    PeImportBinding,
    PeImportService,
    bind_pe32_imports,
    parse_pe32_imports,
)

PE32_MAGIC: int = 0x10B
"""Optional-header magic for a 32-bit PE image; 0x20B (PE32+) is refused."""

PE32_MACHINE_I386: int = 0x14C
"""FILE_HEADER.Machine value for genuine i386 images."""

IMAGE_FILE_EXECUTABLE_IMAGE: int = 0x0002
IMAGE_FILE_DLL: int = 0x2000

EFLAGS_RESERVED_BIT1: int = 0x2
"""EFLAGS bit 1 is reserved and architecturally always set."""

STACK_ANCHOR_BYTES: int = 4
"""ESP must anchor at least one declared dword of readable+writable memory."""

PE32_BOOT_REGISTERS: frozenset[str] = frozenset(REGISTER_IDS)
"""The exact caller-declared flat32 boot register file: all general-purpose
integer registers plus EFLAGS, each exactly once at full 32-bit width."""

REFUSED_DIRECTORY_ENTRIES: dict[int, str] = {
    1: "import",
    9: "tls",
    10: "load_config",
    11: "bound_import",
    12: "iat",
    13: "delay_import",
    14: "clr",
}
"""Optional-header data directories that encode initialization-time effects
(import binding, TLS callbacks, load-config hardening state, CLR startup)
this contract cannot yet initialize, so their presence is refused rather than
silently skipped."""


def _checked_u32(value: int, name: str) -> int:
    """Validate one flat 32-bit domain field, rejecting bool masquerades."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{name} must be a 32-bit unsigned integer")
    return value


def _checked_registers(registers: tuple[tuple[str, int], ...]) -> tuple[tuple[str, int], ...]:
    """Validate and normalize the exact 32-bit boot register file declaration.

    Every name in ``PE32_BOOT_REGISTERS`` must appear exactly once; no
    loader-owned register (EIP or segment selectors) may be declared because
    this contract owns no synthetic reset vector or segment state. Declared
    EFLAGS must carry the architecturally reserved bit 1 — the environment is
    exact, so the bit is required rather than silently forced.
    """
    names: list[str] = []
    pairs: list[tuple[str, int]] = []
    for pair in registers:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise ValueError("registers must be (name, value) pairs")
        name, value = pair
        if not isinstance(name, str):
            raise ValueError("register names must be strings")
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("register values must be integers, never bool")
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("register values are full 32-bit widths")
        names.append(name)
        pairs.append((name, value))
    if len(names) != len(set(names)) or set(names) != PE32_BOOT_REGISTERS:
        raise ValueError(
            "registers must declare eax,ebx,ecx,edx,esi,edi,ebp,esp,eflags exactly once"
        )
    if not dict(pairs)["eflags"] & EFLAGS_RESERVED_BIT1:
        raise ValueError("declared eflags must carry the architecturally reserved bit 1")
    return tuple(pairs)


def _checked_memory(memory: tuple[PeProgramMemory, ...]) -> tuple[PeProgramMemory, ...]:
    """Validate, bound and sort the declared preinitialized allocations.

    Count and aggregate bytes share the flat32 replay budgets so declared
    metadata cannot exceed finite intake work. Regions are normalized into
    ascending address order; any overlap between two declared allocations is
    ambiguous initial state and is refused.
    """
    regions: list[PeProgramMemory] = []
    for region in memory:
        if not isinstance(region, PeProgramMemory):
            raise ValueError("environment memory entries must be PeProgramMemory regions")
        regions.append(region)
    if len(regions) > MAX_PAGE_CLAIMS:
        raise ValueError("environment memory region count exceeds the intake budget")
    if sum(len(region.data) for region in regions) > MAX_MAPPED_BYTES:
        raise ValueError("environment memory bytes exceed the 64 MiB budget")
    ordered = tuple(sorted(regions, key=lambda region: region.address))
    for previous, current in pairwise(ordered):
        if current.address < previous.end():
            raise ValueError("environment memory regions may not overlap")
    return ordered


@dataclass(frozen=True, slots=True)
class PeProgramMemory:
    """One exact, complete, preinitialized non-executable data allocation.

    ``data`` contains every initial byte of the range — nothing is appended,
    zero-filled or inferred. ``access`` is the declared guest access for the
    range and may never request ``EXECUTE``: executable caller memory would
    bypass the file-declared code contract. An allocation is complete in
    itself; it does not create or widen mappings outside its own bytes.
    """

    address: int
    data: bytes
    access: DeclaredAccess

    def __post_init__(self) -> None:
        """Validate the allocation shape, access and 32-bit bounds."""
        _checked_u32(self.address, "memory address")
        if not isinstance(self.access, DeclaredAccess):
            raise ValueError("memory access requires a typed DeclaredAccess")
        known = DeclaredAccess.READ | DeclaredAccess.WRITE | DeclaredAccess.EXECUTE
        if int(self.access) & ~int(known):
            raise ValueError("memory access names bits outside the declared permission set")
        if self.access & DeclaredAccess.EXECUTE:
            raise ValueError("environment memory is data-only; EXECUTE is never granted")
        if not isinstance(self.data, (bytes, bytearray)):
            raise ValueError("memory data must be the exact initial bytes")
        object.__setattr__(self, "data", bytes(self.data))
        if not 0 < len(self.data) <= MAX_MAPPED_BYTES:
            raise ValueError("memory data must be a positive length within the 64 MiB budget")
        if self.address + len(self.data) > 2**32:
            raise ValueError("memory range must stay inside the 32-bit flat space")

    def end(self) -> int:
        """Return the exclusive end offset; cannot wrap past the 32-bit space."""
        return self.address + len(self.data)

    def contains(self, address: int, size: int = 1) -> bool:
        """Test containment of ``[address, address+size)`` without wrapping."""
        return self.address <= address and address + size <= self.end()

    def declared_region(self) -> DeclaredRegion:
        """Project this allocation into the shared declared-region permission plan.

        Environment memory is caller-declared data scratch: the ``VECTOR``
        origin keeps it bounded by file coverage under ``plan_page_grants``
        instead of inventing a new permission role.
        """
        return DeclaredRegion(self.address, len(self.data), self.access, MappingOrigin.VECTOR)


def _checked_services(
    services: tuple[PeImportService, ...], exit_address: int
) -> tuple[PeImportService, ...]:
    """Validate the bounded declared import-service set.

    Declarations are opt-in and exact: each entry must be a typed
    ``PeImportService``, the ``dll!name`` identities and synthetic boundary
    addresses must be pairwise distinct, and no service address may alias
    the declared exit gateway — overlapping boundaries are ambiguous, never
    merged.
    """
    if len(services) > MAX_IMPORT_BINDINGS:
        raise ValueError("declared import-service count exceeds the intake budget")
    ordered: list[PeImportService] = []
    keys: set[tuple[str, str]] = set()
    addresses: set[int] = set()
    for service in services:
        if not isinstance(service, PeImportService):
            raise ValueError("environment services must be typed PeImportService contracts")
        if service.key() in keys:
            raise ValueError("declared import services must have distinct dll!name identities")
        keys.add(service.key())
        if service.address in addresses or service.address == exit_address:
            raise ValueError("declared service addresses must be distinct from each other and exit")
        addresses.add(service.address)
        ordered.append(service)
    return tuple(ordered)


@dataclass(frozen=True, slots=True)
class PeProgramEnvironment:
    """Caller-declared complete initial register file, data allocations and exit.

    ``registers`` declares eax, ebx, ecx, edx, esi, edi, ebp, esp and eflags
    exactly once each at full 32-bit width; there are no defaults. ``memory``
    is the complete set of caller-preinitialized data allocations — the
    environment supplies every byte the program may read outside the image,
    including the stack location ``esp`` points at. At least
    ``STACK_ANCHOR_BYTES`` starting at ``esp`` must lie inside a declared
    readable+writable allocation; no stack is manufactured here.

    ``exit_address`` is an explicit synthetic environment terminal boundary:
    the parent uses it as the ExitProcess-shaped stdcall target that ends
    program execution. It is caller-declared, never guessed from code or
    names, and must lie outside every declared allocation and outside the
    loaded image bytes (enforced once the image is known).

    ``services`` is the optional bounded import declaration: typed
    ``dll!name`` returning-service contracts whose declared synthetic
    addresses are sealed into the loaded IAT. When empty (the default) any
    import/IAT directory refuses the boot; when nonempty the declared set
    must cover every admitted raw import exactly and each service address
    must be distinct from ``exit_address``, every other service and every
    declared allocation.
    """

    registers: tuple[tuple[str, int], ...]
    memory: tuple[PeProgramMemory, ...]
    exit_address: int
    services: tuple[PeImportService, ...] = ()

    def __post_init__(self) -> None:
        """Validate the complete register file, allocations, terminal, services."""
        _checked_u32(self.exit_address, "exit_address")
        object.__setattr__(self, "registers", _checked_registers(self.registers))
        object.__setattr__(self, "memory", _checked_memory(self.memory))
        object.__setattr__(self, "services", _checked_services(self.services, self.exit_address))
        for region in self.memory:
            if region.contains(self.exit_address):
                raise ValueError("exit_address must lie outside declared environment data")
            for service in self.services:
                if region.contains(service.address):
                    raise ValueError("service addresses must lie outside declared environment data")
        esp = dict(self.registers)["esp"]
        anchored = any(
            region.contains(esp, STACK_ANCHOR_BYTES)
            and region.access & DeclaredAccess.READ
            and region.access & DeclaredAccess.WRITE
            for region in self.memory
        )
        if not anchored:
            raise ValueError(
                "esp must anchor at least 4 bytes of declared readable+writable memory"
            )

    def declared_regions(self) -> tuple[DeclaredRegion, ...]:
        """Project every allocation into the shared declared-region plan."""
        return tuple(region.declared_region() for region in self.memory)


@dataclass(frozen=True, slots=True)
class PeProgramBoot:
    """PE32 whole-program boot contract bound to one exact input snapshot.

    ``image`` is the admitted main-image snapshot: file-declared permission
    regions, executable ranges and only the main object's loaded bytes —
    synthetic loader backers (extern stubs, TLS objects) are excluded. When
    the environment declares import services, the loaded bytes already carry
    each declared service address sealed into its actual IAT slot.
    ``entry`` is the loaded linear entry point inside a declared executable
    range. ``environment`` is the caller-declared register file, complete
    preinitialized allocations and explicit exit terminal. ``imports`` is
    the bound routing evidence: every admitted raw import symbol grouped
    under its exactly matching declared service. ``file_sha256``
    binds the serialized PE32 bytes; ``boot_sha256`` binds the file hash, the
    admitted loaded bytes, the declared permissions, the entry point and the
    complete environment, so the identity cannot be shared across changed
    bytes or changed declared initial state.
    """

    image: ReplayImage
    entry: int
    environment: PeProgramEnvironment
    file_sha256: str
    boot_sha256: str
    imports: tuple[PeImportBinding, ...] = ()

    def __post_init__(self) -> None:
        """Require the typed contract fields and a bound identity."""
        if (
            not isinstance(self.image, ReplayImage)
            or not isinstance(self.environment, PeProgramEnvironment)
            or isinstance(self.entry, bool)
            or not isinstance(self.entry, int)
        ):
            raise ValueError("program boot requires a typed image, entry and environment")
        if any(not isinstance(binding, PeImportBinding) for binding in self.imports):
            raise ValueError("program boot requires typed PeImportBinding records")
        _checked_u32(self.entry, "entry")
        if (
            not isinstance(self.file_sha256, str)
            or not isinstance(self.boot_sha256, str)
            or not self.file_sha256
            or not self.boot_sha256
        ):
            raise ValueError("boot identity must bind the file and boot state")
        if not any(start <= self.entry < start + len(data) for start, data in self.image.chunks):
            raise ValueError("entry must be backed by actual loaded image bytes")
        _check_environment_against_image(self.environment, self.image)
        if _boot_identity(self.image, self.entry, self.environment, self.file_sha256) != self.boot_sha256:
            raise ValueError("PE boot identity is stale for its entry, bytes or environment")


def _refuse_unsupported_pe32(data: bytes, *, allow_imports: bool) -> pefile.PE:
    """Refuse non-i386-PE32 inputs and directories encoding startup effects.

    Raw ``pefile`` metadata is read before any CLE loading so that imports,
    TLS callbacks, load-config state or CLR startup are refused as typed
    evidence instead of being silently skipped or bound to CLE fake imports.
    The import and IAT directories are admitted only under an explicit
    declared-service environment (``allow_imports``); every other
    initialization-effect directory is always refused. Returns the parsed
    metadata so the import intake consumes the same evidence.
    """
    try:
        parsed = pefile.PE(data=data, fast_load=not allow_imports)
    except pefile.PEFormatError as ex:
        raise ValueError("input is not a loadable PE image") from ex
    if allow_imports:
        try:
            parsed.parse_data_directories()
        except pefile.PEFormatError as ex:
            raise ValueError("PE32 import metadata is not parseable") from ex
    # pefile Structure fields are dynamic third-party attributes resolved from
    # parsed format metadata; keep that boundary explicit and confined here.
    header = cast(Any, parsed.FILE_HEADER)
    optional = cast(Any, parsed.OPTIONAL_HEADER)
    if optional is None or optional.Magic != PE32_MAGIC:
        raise ValueError("PE32 program boot requires a genuine 32-bit PE image")
    if header is None or header.Machine != PE32_MACHINE_I386:
        raise ValueError("PE32 program boot requires an i386 executable")
    if not header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE or header.Characteristics & IMAGE_FILE_DLL:
        raise ValueError("PE32 program boot requires a non-DLL executable image")
    refused = sorted(
        REFUSED_DIRECTORY_ENTRIES[index]
        for index, entry in enumerate(optional.DATA_DIRECTORY)
        if index in REFUSED_DIRECTORY_ENTRIES
        and (entry.VirtualAddress or entry.Size)
        and not (allow_imports and index in (1, 12))
    )
    if refused:
        raise ValueError(
            "PE32 program boot refuses directories needing initialization services: "
            + ", ".join(refused)
        )
    return parsed


def _load_project(data: bytes) -> angr.Project:
    """Load the PE32 through the bounded InclusivePE backend, never libraries."""
    try:
        return angr.Project(
            io.BytesIO(data),
            auto_load_libs=False,
            main_opts={"backend": InclusivePE, "max_mapped_bytes": MAX_MAPPED_BYTES},
        )
    except CLEError as ex:
        raise ValueError("PE32 image failed bounded loading") from ex


def _seal_iat_slot(
    chunks: list[tuple[int, bytes]], slot: int, address: int
) -> None:
    """Write one declared service address into its actual loaded IAT slot.

    The slot must lie inside one admitted main-image chunk — outside the
    loaded bytes it is unproven loader evidence and refuses rather than
    patching nothing.
    """
    for index, (start, data) in enumerate(chunks):
        if start <= slot and slot + 4 <= start + len(data):
            patched = bytearray(data)
            patched[slot - start : slot - start + 4] = struct.pack("<I", address)
            chunks[index] = (start, bytes(patched))
            return
    raise ValueError(f"import slot {hex(slot)} is outside the loaded image bytes")


def _check_iat_region(image: ReplayImage, bindings: tuple[PeImportBinding, ...]) -> None:
    """Require every bound IAT slot to stay inside readable non-executable data.

    A slot inside a declared executable range is ambiguous (the program
    could legally execute or self-modify it), and a slot without declared
    readable access can never route the call — both refuse at intake.
    """
    for binding in bindings:
        for slot in binding.slots:
            if any(region.address < slot + 4 and slot < region.address + region.size
                   for region in image.executable):
                raise ValueError("import slots may not overlap executable image ranges")
            readable = any(
                region.access & DeclaredAccess.READ
                and region.address <= slot and slot + 4 <= region.address + region.size
                for region in image.declared
            )
            if not readable:
                raise ValueError("import slots require file-declared readable coverage")


def _admitted_image(project: angr.Project, bindings: tuple[PeImportBinding, ...]) -> ReplayImage:
    """Snapshot the loaded image, seal declared IAT slots, keep main bytes only.

    ``image_from_project`` captures every loader backer, including CLE
    synthetic objects (``cle##externs``, ``cle##tls``) mapped outside the
    main object. Those are initialization-service state, not program bytes:
    they are excluded so only main-image bytes are admitted. A backer that
    straddles the main-object span is loader evidence this contract cannot
    classify, so it is refused rather than trimmed. Declared service
    addresses are then sealed into the actual IAT slots inside the admitted
    bytes — CLE extern stub values are overwritten, never consumed.
    """
    image = image_from_project(project)
    main = project.loader.main_object
    low, high = int(main.min_addr), int(main.max_addr)
    chunks: list[tuple[int, bytes]] = []
    for address, data in image.chunks:
        if address + len(data) <= low or high < address:
            continue
        if not (low <= address and address + len(data) <= high + 1):
            raise ValueError("loader backer straddles the main image span")
        chunks.append((address, bytes(data)))
    for binding in bindings:
        for slot in binding.slots:
            _seal_iat_slot(chunks, slot, binding.service.address)
    admitted = ReplayImage(tuple(chunks), image.executable, image.declared)
    _check_iat_region(admitted, bindings)
    return admitted


def _check_environment_against_image(environment: PeProgramEnvironment, image: ReplayImage) -> None:
    """Refuse declared state that collides with the admitted loaded bytes."""
    loaded = tuple((address, address + len(data)) for address, data in image.chunks)
    for region in environment.memory:
        if any(region.address < end and start < region.end() for start, end in loaded):
            raise ValueError("environment memory may not overlap loaded image bytes")
    if any(start <= environment.exit_address < end for start, end in loaded):
        raise ValueError("exit_address must lie outside loaded image bytes")
    for service in environment.services:
        if any(start <= service.address < end for start, end in loaded):
            raise ValueError("service addresses must lie outside loaded image bytes")


def _environment_identity(environment: PeProgramEnvironment) -> bytes:
    """Hash the complete declared initial state: registers, allocations, exit.

    Declared import services join the identity only when present, so every
    declared response, volatile policy, flag policy and boundary address
    distinguishes the environment — differing declarations can never share
    a joint premise.
    """
    digest = hashlib.sha256()
    digest.update(canonical_json_bytes(sorted(environment.registers)))
    digest.update(environment.exit_address.to_bytes(8, "little"))
    for region in environment.memory:
        digest.update(region.address.to_bytes(8, "little"))
        digest.update(len(region.data).to_bytes(8, "little"))
        digest.update(int(region.access).to_bytes(4, "little"))
        digest.update(region.data)
    if environment.services:
        digest.update(
            canonical_json_bytes([service.declared_fields() for service in environment.services])
        )
    return digest.digest()


def _boot_identity(
    image: ReplayImage, entry: int, environment: PeProgramEnvironment, file_sha256: str
) -> str:
    """Bind file hash, admitted bytes, permissions, entry and environment.

    The loaded-byte digest covers every admitted chunk's address, length and
    content, and the structural record covers the entry point and the full
    declared permission evidence, so two boots with different bytes, access
    declarations or initial state can never share an identity.
    """
    loaded = hashlib.sha256()
    for address, data in image.chunks:
        loaded.update(address.to_bytes(8, "little"))
        loaded.update(len(data).to_bytes(8, "little"))
        loaded.update(data)
    structural = canonical_json_bytes(
        {
            "entry": entry,
            "executable": [[region.address, region.size] for region in image.executable],
            "declared": [
                [region.address, region.size, int(region.access), str(region.origin)]
                for region in image.declared
            ],
            "loaded_sha256": loaded.hexdigest(),
        }
    )
    return hashlib.sha256(
        bytes.fromhex(file_sha256) + structural + _environment_identity(environment)
    ).hexdigest()


def pe_program_from_bytes(data: bytes, environment: PeProgramEnvironment) -> PeProgramBoot:
    """Derive the PE32 whole-program boot contract from actual file bytes.

    The file must be a genuine i386 PE32 EXE with no initialization-service
    directories; it is loaded through the bounded ``InclusivePE`` backend
    with no library loading. The admitted image keeps only main-object
    bytes — synthetic loader backers are excluded — and the loaded entry
    must land inside a declared executable byte range. The environment
    declares every register and every non-image initial byte; its
    allocations may not overlap loaded bytes and its ``exit_address`` must
    lie outside both. No memory is written, no caller frame or return trap
    is installed, and no stack is manufactured. When the environment opts in
    with declared ``services``, the raw import directory must bind to them
    exactly and their declared addresses are sealed into the loaded IAT —
    never sourced from CLE extern stubs.
    """
    if not isinstance(environment, PeProgramEnvironment):
        raise ValueError("program boot requires a declared PeProgramEnvironment")
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("PE32 program bytes must be exact file bytes")
    if len(data) > MAX_MAPPED_BYTES:
        raise ValueError("PE file input exceeds the bounded byte budget")
    data = bytes(data)
    parsed = _refuse_unsupported_pe32(data, allow_imports=bool(environment.services))
    bindings: tuple[PeImportBinding, ...] = ()
    if environment.services:
        bindings = bind_pe32_imports(parse_pe32_imports(parsed), environment.services)
    project = _load_project(data)
    image = _admitted_image(project, bindings)
    entry = int(project.loader.main_object.entry)
    if not any(region.contains(entry) for region in image.executable):
        raise ValueError("entry point is outside declared executable loaded bytes")
    _check_environment_against_image(environment, image)
    file_sha256 = hashlib.sha256(data).hexdigest()
    return PeProgramBoot(
        image=image,
        entry=entry,
        environment=environment,
        file_sha256=file_sha256,
        boot_sha256=_boot_identity(image, entry, environment, file_sha256),
        imports=bindings,
    )
