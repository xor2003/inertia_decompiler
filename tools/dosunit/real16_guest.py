"""Fresh segmented guest setup for independent real16 replay.

Layer: dosunit concrete execution.
Responsibility: validate vectors, map declared memory, and initialize registers,
loaded program bytes and architectural caller frames in a fresh Unicorn guest.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tools.dosunit.real16_replay_model import (
    GENERAL_REGS,
    HIGH_REGS,
    ONE_MIB,
    PAGE_SIZE,
    VECTOR_SEGMENTS,
    A20Policy,
    FrameKind,
    LinearRange,
    Real16Image,
    Real16ReplayPolicy,
    Real16Vector,
    SegOffset,
)

if TYPE_CHECKING:
    import unicorn
    from unicorn import x86_const as registers
    from unicorn.unicorn_py3.unicorn import Uc
else:
    try:
        import unicorn
        from unicorn import x86_const as registers
        from unicorn.unicorn_py3.unicorn import Uc
    except ImportError:
        unicorn = None  # type: ignore[assignment]
        registers = None  # type: ignore[assignment]
        Uc = None  # type: ignore[assignment, misc]

def _segment_ids() -> dict[str, int]:
    """Map logical segment names to their emulator register identities."""
    return {
        "cs": registers.UC_X86_REG_CS, "ds": registers.UC_X86_REG_DS,
        "es": registers.UC_X86_REG_ES, "ss": registers.UC_X86_REG_SS,
        "fs": registers.UC_X86_REG_FS, "gs": registers.UC_X86_REG_GS,
    }

def _high_ids() -> dict[str, int]:
    """Map high-half names to the full 32-bit register identities."""
    return {
        "eax": registers.UC_X86_REG_EAX, "ebx": registers.UC_X86_REG_EBX,
        "ecx": registers.UC_X86_REG_ECX, "edx": registers.UC_X86_REG_EDX,
        "esi": registers.UC_X86_REG_ESI, "edi": registers.UC_X86_REG_EDI,
        "ebp": registers.UC_X86_REG_EBP, "esp": registers.UC_X86_REG_ESP,
    }


def _low_ids() -> dict[str, int]:
    """Bind admitted word registers to explicit Unicorn register constants."""
    return {
        "ax": registers.UC_X86_REG_AX, "bx": registers.UC_X86_REG_BX,
        "cx": registers.UC_X86_REG_CX, "dx": registers.UC_X86_REG_DX,
        "si": registers.UC_X86_REG_SI, "di": registers.UC_X86_REG_DI,
        "bp": registers.UC_X86_REG_BP, "sp": registers.UC_X86_REG_SP,
    }

def _seg_write(guest: Uc, seg_offset: SegOffset, data: bytes) -> None:
    """Resolve the starting offset once, then write contiguous physical bytes."""
    guest.mem_write(seg_offset.linear(), data)

def _seg_read(guest: Uc, seg_offset: SegOffset, size: int) -> bytes:
    """Read the declared contiguous range under LINEAR_CONTINUE semantics."""
    return bytes(guest.mem_read(seg_offset.linear(), size))

def _checked_register_contract(
    vector: Real16Vector,
) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    """Validate register names, widths and duplicates in the vector."""
    regs = dict(vector.registers)
    segments = dict(vector.segments)
    highs = dict(vector.high_halves)
    if len(regs) != len(vector.registers) or set(regs) - set(GENERAL_REGS) - {"flags"}:
        raise ValueError("duplicate or unsupported real16 input register")
    if len(segments) != len(vector.segments) or set(segments) - set(VECTOR_SEGMENTS):
        raise ValueError("duplicate or unsupported real16 input segment (cs comes from entry)")
    if len(highs) != len(vector.high_halves) or set(highs) - set(HIGH_REGS) - {"eflags"}:
        raise ValueError("duplicate or unsupported real16 high-half register")
    for values, what in ((regs, "real16 registers"), (segments, "real16 segment registers"),
                         (highs, "386 high halves")):
        if any(not 0 <= value <= 0xFFFF for value in values.values()):
            raise ValueError(f"{what} are 16-bit")
    if regs.get("sp", 0) == 0:
        raise ValueError("sp must be non-zero so the caller frame can be installed")
    return regs, segments, highs

def _checked_frame(vector: Real16Vector, entry: SegOffset, regs: dict[str, int],
                   segments: dict[str, int], policy: Real16ReplayPolicy) -> None:
    """Validate the caller frame against the entry contract and policies."""
    if vector.frame.kind is FrameKind.NEAR16 and vector.frame.target.segment != entry.segment:
        raise ValueError("near16 frame target must share the entry code segment")
    frame_size = len(vector.frame.push_bytes())
    sp = regs["sp"]
    if (sp + frame_size) & 0xFFFF <= sp:
        raise ValueError("caller frame wraps the stack segment")
    if (
        policy.a20 is A20Policy.DISABLED_REFUSE
        and segments.get("ss", 0) * 16 + sp + frame_size > ONE_MIB
    ):
        raise ValueError("caller frame crosses the A20 boundary under disabled policy")

def _checked_regions(
    image: Real16Image, entry: SegOffset, vector: Real16Vector, policy: Real16ReplayPolicy,
) -> None:
    """Validate declared byte regions against code ranges and the A20 policy."""
    if sum(len(data) for _, data in vector.memory) > policy.max_patch_bytes:
        raise ValueError("memory patches exceed the declared patch budget")
    if sum(size for _, size in vector.observations) > policy.max_observation_bytes:
        raise ValueError("observations exceed the declared observation budget")
    for address, size in (
        *((patch.segment * 16 + patch.offset, len(data)) for patch, data in vector.memory),
        *((obs.segment * 16 + obs.offset, size) for obs, size in vector.observations),
    ):
        if policy.a20 is A20Policy.DISABLED_REFUSE and address + size > ONE_MIB:
            raise ValueError("declared region crosses the A20 boundary under disabled policy")
        if any(region.overlaps(address, size) for region in image.code_ranges):
            raise ValueError("declared memory region overlaps instruction bytes")
    if not any(region.contains(entry.linear()) for region in image.code_ranges):
        raise ValueError("entry is outside declared code ranges")
    trap = vector.frame.target.linear()
    if any(address <= trap < address + len(data) for address, data in image.chunks):
        raise ValueError("return trap overlaps loaded image bytes")

def _checked_vector(
    image: Real16Image, entry: SegOffset, vector: Real16Vector, policy: Real16ReplayPolicy,
) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    """Validate the concrete contract before any guest state exists."""
    regs, segments, highs = _checked_register_contract(vector)
    _checked_frame(vector, entry, regs, segments, policy)
    _checked_regions(image, entry, vector, policy)
    return regs, segments, highs

def _pages(address: int, size: int) -> range:
    """Return the page-aligned span covering a physical byte range."""
    first = address // PAGE_SIZE * PAGE_SIZE
    last = (address + size - 1) // PAGE_SIZE * PAGE_SIZE
    return range(first, last + PAGE_SIZE, PAGE_SIZE)

def _declared_segment_range(seg_offset: SegOffset, size: int) -> list[LinearRange]:
    """Resolve a declared byte range under the linear straddle policy."""
    return [LinearRange(seg_offset.linear(), size)]

def _map_guest(
    guest: Uc, image: Real16Image, vector: Real16Vector, policy: Real16ReplayPolicy,
) -> None:
    """Map declared bytes and segment-addressable pages under the A20 policy.

    Declared byte regions (image, BSS, patches, observations, return trap)
    must fit the policy outright; under ``DISABLED_REFUSE`` a crossing is a
    contract error. Declared *segment* regions describe addressable space, so
    only their in-policy pages are mapped; a runtime access beyond the
    boundary then reaches the invalid-access hook and stays a typed outcome.
    """
    limit = ONE_MIB if policy.a20 is A20Policy.DISABLED_REFUSE else None
    segments = dict(vector.segments)
    declared: list[LinearRange] = [
        *[LinearRange(address, len(data)) for address, data in image.chunks],
        LinearRange(vector.frame.target.linear(), 1),
    ]
    if image.bss_size:
        base = image.chunks[0][0] + image.image_size
        declared.append(LinearRange(base, image.bss_size))
    for patch, data in vector.memory:
        declared.extend(_declared_segment_range(patch, len(data)))
    for obs, size in vector.observations:
        declared.extend(_declared_segment_range(obs, size))
    pages: set[int] = set()
    for region in declared:
        if limit is not None and region.address + region.size > limit:
            raise ValueError("declared region crosses the A20 boundary under disabled policy")
        pages.update(_pages(region.address, region.size))
    pages.update(_segment_pages(vector, segments, limit))
    for address in sorted(pages):
        if limit is not None and address >= limit:
            continue
        guest.mem_map(address, PAGE_SIZE)


def _segment_pages(vector: Real16Vector, segments: dict[str, int], limit: int | None) -> set[int]:
    """Map addressable segment pages, leaving out-of-policy accesses explicit."""
    bases = {patch.segment for patch, _ in vector.memory}
    bases.update(obs.segment for obs, _ in vector.observations)
    # Omitted segments are initialized to zero, so that segment's addressable
    # pages must exist just as if the manifest explicitly supplied zero.
    bases.update(segments.get(name, 0) for name in VECTOR_SEGMENTS)
    pages: set[int] = set()
    for value in bases:
        start, end = value * 16, value * 16 + 0x10000
        if limit is not None:
            end = min(end, limit)
        if start < end:
            pages.update(_pages(start, end - start))
    return pages

def _initialize_guest(
    image: Real16Image, entry: SegOffset, vector: Real16Vector,
    policy: Real16ReplayPolicy,
) -> Uc:
    """Create a fresh guest seeded with the relocated image and contract."""
    regs, segments, highs = _checked_vector(image, entry, vector, policy)
    guest = Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_16)
    _map_guest(guest, image, vector, policy)
    for address, data in image.chunks:
        guest.mem_write(address, data)
    for patch, data in vector.memory:
        _seg_write(guest, patch, data)
    _seg_write(
        guest,
        SegOffset(segments.get("ss", 0), regs["sp"]),
        vector.frame.push_bytes(),
    )
    high_ids = _high_ids()
    low_ids = _low_ids()
    for index, name in enumerate(GENERAL_REGS):
        high_name = HIGH_REGS[index]
        value = regs.get(name, 0) | (highs.get(high_name, 0) << 16)
        guest.reg_write(high_ids[high_name], value)
        guest.reg_write(low_ids[name], regs.get(name, 0))
    for name, identity in _segment_ids().items():
        if name == "cs":
            guest.reg_write(identity, entry.segment)
        else:
            guest.reg_write(identity, segments.get(name, 0))
    guest.reg_write(registers.UC_X86_REG_IP, entry.offset)
    guest.reg_write(
        registers.UC_X86_REG_EFLAGS,
        (regs.get("flags", 0x0002) | (highs.get("eflags", 0) << 16)) | 0x0002,
    )
    return guest
