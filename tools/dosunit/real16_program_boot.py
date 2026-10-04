"""Binary-derived initialized MZ boot state for independent whole-program replay.

Layer: dosunit concrete execution.
Responsibility: derive the DOS EXE boot contract — the PSP-anchored arena,
the relocated load module at PSP+0x10 paragraphs, header CS:IP and SS:SP, and
the caller-declared initial register file — from actual MZ bytes and a
declared ``ProgramEnvironment``. This owner constructs boot state only: it
writes no memory, installs no caller or return frame, and synthesizes no DOS
state (PSP fields, command tail, environment pointers, register defaults).
Every initial byte of the arena and every register value is declared
environment supplied by the caller, not inferred universal DOS loader
behavior.

"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from angr_platforms.X86_16.mz_invocation_source import mz_boot_coordinates_8616

from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.real16_mz_load import MzExe, image_from_mz_bytes, parse_mz
from tools.dosunit.real16_program_device_info import DeviceInfoPolicy, device_info_policy_document
from tools.dosunit.real16_program_input import InputPolicy
from tools.dosunit.real16_program_input_manifest import input_policy_document
from tools.dosunit.real16_program_memory import (
    InitialMemoryRegion,
    ProgramMemoryLayout,
    memory_regions_document,
    program_memory_layout,
)
from tools.dosunit.real16_program_output import OutputPolicy
from tools.dosunit.real16_program_resize import TailResizePolicy, resize_policy_document
from tools.dosunit.real16_program_rom import ProgramRom, check_rom, rom_document
from tools.dosunit.real16_program_vectors import VectorPolicy, check_vector_policy, vector_policy_document
from tools.dosunit.real16_program_version import VersionPolicy, version_policy_document
from tools.dosunit.real16_program_video import VideoQueryPolicy, video_policy_document
from tools.dosunit.real16_program_video_boundary import VIDEO_VECTOR_RANGE, check_video_policy
from tools.dosunit.real16_program_video_state import VideoStatePolicy, video_state_document
from tools.dosunit.real16_replay_model import LinearRange, Real16Image, SegOffset
from tools.dosunit.real16_video_state_boundary import VIDEO_BDA_MODE, VIDEO_BDA_ROWS

PSP_PARAGRAPHS: int = 0x10
PSP_BYTES: int = PSP_PARAGRAPHS * 16
# End of conventional memory: the video RAM arena begins at 0xA0000, so a
# DOS program arena may end at, never cross, this physical boundary.
CONVENTIONAL_CEILING: int = 0xA0000

# The environment declares the full 386 register file the DOS loader does not
# own: the general registers as whole 32-bit values plus EFLAGS. Segment
# registers are deliberately absent — CS:IP and SS:SP are loader-owned by the
# header, DS/ES are loader-owned by the PSP, and FS/GS are explicit
# environment fields, so no register entry may override an owned segment or
# the entry point.
BOOT_REGISTERS: frozenset[str] = frozenset({
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags",
})


def _checked_u16(value: int, name: str) -> int:
    """Validate one 16-bit domain field, rejecting bool masquerades."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF:
        raise ValueError(f"{name} must be a 16-bit unsigned integer")
    return value


def _checked_registers(
    registers: tuple[tuple[str, int], ...],
) -> tuple[tuple[str, int], ...]:
    """Validate and normalize the exact 32-bit register file declaration.

    Every name in ``BOOT_REGISTERS`` must appear exactly once at full 32-bit
    width; a name outside the set would try to override a loader-owned
    segment or the entry point and is refused. ``esp`` must have a zero upper
    half in this real16 scope because its lower half is superseded by the
    authoritative header SP at boot.
    """
    names: list[str] = []
    pairs: list[tuple[str, int]] = []
    for pair in registers:
        name, value = pair
        if not isinstance(name, str):
            raise ValueError("register names must be strings")
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("register values must be integers, never bool")
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("register values are full 32-bit widths")
        names.append(name)
        pairs.append((name, value))
    if len(names) != len(set(names)) or set(names) != BOOT_REGISTERS:
        raise ValueError(
            "registers must declare eax,ebx,ecx,edx,esi,edi,ebp,esp,eflags exactly once"
        )
    if dict(pairs)["esp"] > 0xFFFF:
        raise ValueError("esp upper half must be zero for the real16 boot scope")
    return tuple(pairs)


@dataclass(frozen=True, slots=True)
class ProgramEnvironment:
    """Caller-declared DOS pre-load allocation and initial register state.

    ``allocation`` is the exact entire arena DOS granted the program,
    beginning at ``psp_segment``:0 and covering the 256-byte PSP. The caller
    supplies every initial byte; nothing is zero-filled, appended or
    inferred. ``registers`` declares the complete 32-bit register file and
    EFLAGS exactly once each. ``esp`` keeps a zero upper half for the real16
    scope, and its lower half is not authoritative — the header SP overrides
    it when the boot contract is derived. ``fs`` and ``gs`` are separate
    fields so no register entry can stand in for a loader-owned segment.
    output_policy explicitly opts into capped successful independent byte streams;
    input_policy separately declares immutable preopened regular files and
    bounded read/seek services. ``version_policy`` independently declares the
    exact INT21/AH30 AL00 response bytes — a bounded caller-supplied answer,
    never a claim about an installed DOS. ``resize_policy`` adds a declared
    first/final native MCB before the arena and bounded tail-block resize;
    the physical bytes stay mapped after shrink. ``extra_memory`` supplies
    disjoint conventional-RAM snapshots outside the allocation; it changes no
    loader grant or executable scope. ``vector_policy`` enables live IVT
    queries/updates under an unchanged declared external DOS entry, with every
    IVT byte supplied through initial memory. ``device_info_policy`` declares
    stable preopened-handle responses to AX4400; it never probes host devices.
    ``video_policy`` declares a stable INT10/AH0F answer under an unchanged
    external BIOS vector. It admits no video-state mutation or handler execution.
    ``video_state_policy`` separately enables AH1B/BX0 functionality tables,
    combining declared static fields with live supplied BDA bytes. A returned
    ROM pointer does not declare or map any ROM memory.
    ``rom`` independently declares exact read-only firmware bytes. They grant
    data reads only, outside the conventional RAM allocation and code scope.
    All policies absent retains termination-
    only service admission.
    """

    psp_segment: int
    allocation: bytes
    registers: tuple[tuple[str, int], ...]
    fs: int
    gs: int
    output_policy: OutputPolicy | None = None
    input_policy: InputPolicy | None = None
    version_policy: VersionPolicy | None = None
    resize_policy: TailResizePolicy | None = None
    extra_memory: tuple[InitialMemoryRegion, ...] = ()
    vector_policy: VectorPolicy | None = None
    device_info_policy: DeviceInfoPolicy | None = None
    video_policy: VideoQueryPolicy | None = None
    video_state_policy: VideoStatePolicy | None = None
    rom: ProgramRom | None = None

    def __post_init__(self) -> None:
        """Validate the arena shape, ceiling and complete register file."""
        if self.output_policy is not None and not isinstance(self.output_policy, OutputPolicy):
            raise ValueError("output_policy requires a typed OutputPolicy")
        if self.input_policy is not None and not isinstance(self.input_policy, InputPolicy):
            raise ValueError("input_policy requires a typed InputPolicy")
        if self.version_policy is not None and not isinstance(self.version_policy, VersionPolicy):
            raise ValueError("version_policy requires a typed VersionPolicy")
        if self.device_info_policy is not None and not isinstance(self.device_info_policy, DeviceInfoPolicy):
            raise ValueError("device_info_policy requires a typed DeviceInfoPolicy")
        _checked_u16(self.psp_segment, "psp_segment")
        _checked_u16(self.fs, "fs")
        _checked_u16(self.gs, "gs")
        if not isinstance(self.allocation, (bytes, bytearray)):
            raise ValueError("allocation must be the exact initial arena bytes")
        object.__setattr__(self, "allocation", bytes(self.allocation))
        size = len(self.allocation)
        if size < PSP_BYTES or size % 16 != 0:
            raise ValueError("allocation must be a positive multiple of 16 covering the PSP")
        if self.psp_segment * 16 + size > CONVENTIONAL_CEILING:
            raise ValueError("arena must end at or below the conventional-memory ceiling")
        object.__setattr__(self, "registers", _checked_registers(self.registers))
        if self.resize_policy is not None:
            if not isinstance(self.resize_policy, TailResizePolicy):
                raise ValueError("resize_policy requires a typed TailResizePolicy")
            self.resize_policy.check_arena(self.psp_segment, size)
        check_vector_policy(self.vector_policy, self.memory_layout())
        check_video_policy(self.video_policy, self.memory_layout())
        self._check_video_state()
        check_rom(self.rom)

    def _check_video_state(self) -> None:
        """Require every live source byte and one coherent BIOS service entry."""
        policy = self.video_state_policy
        if policy is None:
            return
        if not isinstance(policy, VideoStatePolicy):
            raise ValueError("video_state_policy requires a typed VideoStatePolicy")
        memory = self.memory_layout()
        if any(not memory.contains(region.address, region.size)
               for region in (VIDEO_VECTOR_RANGE, VIDEO_BDA_MODE, VIDEO_BDA_ROWS)):
            raise ValueError("video state policy requires complete INT10 vector and BDA bytes")
        if self.video_policy is not None and self.video_policy.entry != policy.entry:
            raise ValueError("video policies must declare the same INT10 entry")

    def memory_layout(self) -> ProgramMemoryLayout:
        """Derive one authoritative byte domain without enlarging the DOS grant."""
        return program_memory_layout(self.psp_segment, self.allocation, self.extra_memory, self.resize_policy)


@dataclass(frozen=True, slots=True)
class ProgramBoot:
    """Whole-program boot contract bound to one exact input snapshot.

    ``image`` is the relocated load module with its declared code ranges and
    fingerprints; ``entry`` and ``stack`` are the authoritative header-derived
    CS:IP and SS:SP logical addresses; ``environment`` is the caller-declared
    arena and register file. ``source`` retains the exact serialized MZ bytes
    every other field was derived from, so construction and later consumption
    can re-derive the header fields, relocation records and image fingerprints
    from actual retained evidence instead of trusting supplied numeric fields.
    ``boot_sha256`` binds the file/image/relocation fingerprints, the header
    boot fields, the declared code ranges and the exact environment bytes and
    registers, so the identity cannot be shared across changed bytes or
    changed declared initial state. A boot object whose fields no longer match
    its retained source — including one rebuilt through ``dataclasses.replace``
    under a stale identity — is refused rather than executed.
    """

    image: Real16Image
    entry: SegOffset
    stack: SegOffset
    environment: ProgramEnvironment
    boot_sha256: str
    source: bytes

    def __post_init__(self) -> None:
        """Require the typed contract fields and a bound identity."""
        if (
            not isinstance(self.image, Real16Image)
            or not isinstance(self.entry, SegOffset)
            or not isinstance(self.stack, SegOffset)
            or not isinstance(self.environment, ProgramEnvironment)
        ):
            raise ValueError("program boot requires typed image, entry, stack and environment")
        if not isinstance(self.source, (bytes, bytearray)) or not self.source:
            raise ValueError("program boot retains the exact source MZ bytes")
        object.__setattr__(self, "source", bytes(self.source))
        if not isinstance(self.boot_sha256, str) or not self.boot_sha256:
            raise ValueError("boot_sha256 must bind the boot identity")
        self._check_against_source()

    def _check_against_source(self) -> None:
        """Re-derive every header-bound field from the retained MZ bytes.

        This is the provenance gate shared by construction and consumption: it
        re-parses the retained source, rebuilds the relocated image under the
        declared load segment and code ranges, and refuses any entry, stack,
        chunk, fingerprint or environment field that does not match the
        re-derived evidence. The arena and identity checks mirror the factory
        contract so a forged or mutated object cannot publish a stale boot
        identity even when ``__post_init__`` was bypassed. All refusals are
        boundary-named ``ValueError`` failures; nothing is guessed or
        defaulted.
        """
        exe = parse_mz(self.source)
        image = self.image
        if (
            not isinstance(image.file_sha256, str)
            or image.file_sha256 != hashlib.sha256(self.source).hexdigest()
        ):
            raise ValueError("boot image file fingerprint is stale for the retained MZ bytes")
        if type(image.load_segment) is not int:
            raise ValueError("boot image load segment must be a 16-bit paragraph")
        if not all(isinstance(region, LinearRange) for region in image.code_ranges):
            raise ValueError("boot image code ranges must be typed linear ranges")
        declared = image.code_ranges if image.code_scope == "declared" else ()
        derived = image_from_mz_bytes(
            self.source, load_segment=image.load_segment, code_ranges=tuple(declared)
        )
        if derived != image or any(
            type(value) is not int
            for value in (image.image_size, image.bss_size)
        ):
            raise ValueError("boot image is stale for the retained MZ bytes")
        coordinates = mz_boot_coordinates_8616(exe, image.load_segment)
        entry = SegOffset(coordinates.entry_segment, coordinates.entry_offset)
        stack = SegOffset(coordinates.stack_segment, coordinates.stack_offset)
        if self.entry != entry or self.stack != stack:
            raise ValueError("boot entry/stack is stale for the retained MZ header")
        _check_arena_bounds(exe, entry, stack, self.environment)
        if _boot_identity(image, exe, self.environment) != self.boot_sha256:
            raise ValueError("MZ boot identity is stale for its entry, bytes or environment")

    def initial_registers(self) -> tuple[tuple[str, int], ...]:
        """Return the declared register file with authoritative header SP applied.

        The environment ``esp`` upper half is contractually zero, so replacing
        the whole value with ``stack.offset`` is exactly the documented
        lower-half override; every other declared register passes through.
        """
        return tuple(
            (name, self.stack.offset if name == "esp" else value)
            for name, value in self.environment.registers
        )


def _check_arena_bounds(
    exe: MzExe, entry: SegOffset, stack: SegOffset, environment: ProgramEnvironment
) -> None:
    """Re-check the arena grant and entry/stack containment contract.

    This mirrors the factory's loader-grant invariants so a boot object built
    or mutated outside ``program_from_mz_bytes`` cannot carry an entry or stack
    the declared arena could never have admitted.
    """
    arena_start = environment.psp_segment * 16
    arena_end = arena_start + len(environment.allocation)
    arena_paragraphs = len(environment.allocation) // 16
    module_paragraphs = (len(exe.image) + 15) // 16
    if arena_paragraphs < PSP_PARAGRAPHS + module_paragraphs + exe.minalloc:
        raise ValueError("arena does not hold the PSP, paragraph-rounded module and declared BSS")
    if arena_paragraphs > PSP_PARAGRAPHS + module_paragraphs + exe.maxalloc:
        raise ValueError("arena exceeds the loader grant bounded by maxalloc")
    if not arena_start <= entry.linear() < arena_end:
        raise ValueError("header entry lies outside the allocated arena")
    # SP 0 is the top-of-segment case: the exclusive top is SS:0x10000.
    stack_top = stack.segment * 16 + (stack.offset if stack.offset else 0x10000)
    if stack_top > arena_end:
        raise ValueError("header stack top lies outside the allocated arena")


def _boot_identity(image: Real16Image, exe: MzExe, environment: ProgramEnvironment) -> str:
    """Bind the image fingerprints, header boot fields and declared environment.

    The digest covers the exact arena bytes and register file (not only the
    loaded code), the declared code ranges, and the raw header fields that
    drove entry/stack derivation, so two boots with different initial state
    can never share an identity.
    """
    structural = canonical_json_bytes({
        "entry": [exe.entry_cs, exe.entry_ip],
        "stack": [exe.stack_ss, exe.stack_sp],
        "alloc": [exe.minalloc, exe.maxalloc],
        "code": [[region.address, region.size] for region in image.code_ranges],
        "scope": image.code_scope,
        "input_policy": input_policy_document(environment.input_policy),
        "output_policy": None if environment.output_policy is None else {
            "handles": sorted(environment.output_policy.handles),
            "per_call_bytes": environment.output_policy.per_call_bytes,
            "aggregate_bytes": environment.output_policy.aggregate_bytes,
        },
        "version_policy": version_policy_document(environment.version_policy),
        "resize_policy": resize_policy_document(environment.resize_policy),
        "extra_memory": memory_regions_document(environment.extra_memory),
        "vector_policy": vector_policy_document(environment.vector_policy),
        "device_info_policy": device_info_policy_document(environment.device_info_policy),
        "video_policy": video_policy_document(environment.video_policy),
        "video_state_policy": video_state_document(environment.video_state_policy),
        "rom": rom_document(environment.rom),
    })
    environment_digest = hashlib.sha256(
        environment.psp_segment.to_bytes(2, "little")
        + environment.fs.to_bytes(2, "little")
        + environment.gs.to_bytes(2, "little")
        + canonical_json_bytes(sorted(environment.registers))
        + environment.allocation
    ).hexdigest()
    return hashlib.sha256(
        bytes.fromhex(image.file_sha256)
        + bytes.fromhex(image.image_sha256)
        + bytes.fromhex(image.reloc_sha256)
        + structural
        + bytes.fromhex(environment_digest)
    ).hexdigest()


def program_from_mz_bytes(
    data: bytes,
    environment: ProgramEnvironment,
    *,
    code_ranges: tuple[LinearRange, ...] = (),
) -> ProgramBoot:
    """Derive the whole-program boot contract from actual MZ bytes.

    The load module lands at ``psp_segment + 0x10`` and is relocated through
    the existing MZ authority; ``code_ranges`` scopes declared instruction
    bytes exactly as in function replay. The arena must hold the PSP, the
    paragraph-rounded module and the declared ``minalloc`` BSS, and may not
    exceed the loader grant bounded by ``maxalloc``. Header CS/SS are added
    to the image paragraph without truncation: a wrapping addition, or an
    entry or stack top outside the allocated arena, is refused. Header SP 0
    is the legitimate top-of-segment pointer, not the function-replay
    ``sp != 0`` rule — the whole 64 KiB stack segment must then remain
    inside the arena, and a top landing exactly at the arena end is allowed.
    No bytes are written and no caller or return frame is installed.
    """
    if not isinstance(environment, ProgramEnvironment):
        raise ValueError("program boot requires a declared ProgramEnvironment")
    exe = parse_mz(data)
    load_segment = environment.psp_segment + PSP_PARAGRAPHS
    if load_segment > 0xFFFF:
        raise ValueError("load module paragraph wraps the 16-bit segment space")
    arena_start = environment.psp_segment * 16
    arena_end = arena_start + len(environment.allocation)
    arena_paragraphs = len(environment.allocation) // 16
    module_paragraphs = (len(exe.image) + 15) // 16
    if arena_paragraphs < PSP_PARAGRAPHS + module_paragraphs + exe.minalloc:
        raise ValueError("arena does not hold the PSP, paragraph-rounded module and declared BSS")
    if arena_paragraphs > PSP_PARAGRAPHS + module_paragraphs + exe.maxalloc:
        raise ValueError("arena exceeds the loader grant bounded by maxalloc")
    image = image_from_mz_bytes(
        data, load_segment=load_segment, code_ranges=tuple(code_ranges)
    )
    coordinates = mz_boot_coordinates_8616(exe, load_segment)
    stack_segment = coordinates.stack_segment
    entry = SegOffset(coordinates.entry_segment, coordinates.entry_offset)
    stack = SegOffset(coordinates.stack_segment, coordinates.stack_offset)
    if not arena_start <= entry.linear() < arena_end:
        raise ValueError("header entry lies outside the allocated arena")
    # The stack area occupies the whole segment below its top. SP 0 is the
    # top-of-segment case: the exclusive top is SS:0x10000, which may land
    # exactly at the arena end. SS is always at or above the image base, so
    # the stack area can never reach below the arena start.
    stack_top = stack_segment * 16 + (exe.stack_sp if exe.stack_sp else 0x10000)
    if stack_top > arena_end:
        raise ValueError("header stack top lies outside the allocated arena")
    return ProgramBoot(
        image=image,
        entry=entry,
        stack=stack,
        environment=environment,
        boot_sha256=_boot_identity(image, exe, environment),
        source=data,
    )
