"""Layer: dosunit concrete replay memory/environment.

Responsibility: bind loaded file declarations and explicit harness roles to
bounded guest mappings, seed bytes without granting access, and capture typed
read-only observation evidence. Unsupported loaded bytes retain their origin.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import unicorn
from unicorn.unicorn_py3.unicorn import Uc

from tools.dosunit.flat32_memory_permissions import (
    MAX_MAPPED_BYTES,
    MAX_PAGE_CLAIMS,
    PAGE_SIZE,
    DeclaredAccess,
    DeclaredRegion,
    MappingOrigin,
    PageGrant,
    plan_page_grants,
)
from tools.dosunit.flat32_replay_model import (
    REGISTER_IDS,
    RETURN_TRAP,
    MemoryObservation,
    MemoryRange,
    ObservationStatus,
    ReplayImage,
    ReplayVector,
)
from tools.dosunit.unicorn_engine import make_guest

if TYPE_CHECKING:
    import angr
    from cle.backends import Backend
    from cle.backends.region import Region


def _region_access(region: Region) -> DeclaredAccess:
    """Read a third-party CLE region's declared permission flags."""
    access = DeclaredAccess.NONE
    if bool(region.is_readable):
        access |= DeclaredAccess.READ
    if bool(region.is_writable):
        access |= DeclaredAccess.WRITE
    if bool(region.is_executable):
        access |= DeclaredAccess.EXECUTE
    return access


def _file_declared_regions(main_object: Backend) -> tuple[DeclaredRegion, ...]:
    """Capture the main image's file-declared permission regions only.

    ELF PT_LOAD segments are the file's loadable mapping declarations; PE
    section headers carry the same role. Backends exposing segments use them
    (CLE's PE backend aliases sections there); otherwise sections are used.
    A segment or section declaring no access is an explicit file denial, not
    absent metadata: it is retained as ``DeclaredAccess.NONE`` so file-page
    resolution denies every harness role sharing the page. Only bytes with
    no file declaration at all stay ``UNSUPPORTED`` rather than acquiring
    invented OS permissions. Synthetic loader objects (externs, TLS, kernel
    stubs) are never file declarations.
    """
    regions: tuple[Region, ...] = tuple(main_object.segments or ())
    if not regions:
        regions = tuple(main_object.sections or ())
    declared: list[DeclaredRegion] = []
    for region in regions:
        if int(region.memsize) > 0:
            declared.append(
                DeclaredRegion(int(region.vaddr), int(region.memsize), _region_access(region), MappingOrigin.FILE)
            )
    return tuple(declared)


def image_from_project(project: angr.Project) -> ReplayImage:
    """Snapshot a supported CLE-loaded i386 image without executing imports."""
    if project.arch.name != "X86":
        raise ValueError("flat32 replay requires an i386 image")
    chunks = tuple((int(address), bytes(data)) for address, data in project.loader.memory.backers())
    executable = tuple(
        MemoryRange(int(section.vaddr), int(section.memsize))
        for section in project.loader.main_object.sections
        if section.is_executable
    )
    if not executable:
        executable = tuple(
            MemoryRange(int(segment.vaddr), int(segment.memsize))
            for segment in project.loader.main_object.segments
            if segment.is_executable
        )
    if not executable:
        raise ValueError("loaded image has no declared executable sections")
    return ReplayImage(chunks, executable, _file_declared_regions(project.loader.main_object))


def _vector_scratch(vector: ReplayVector) -> tuple[DeclaredRegion, ...]:
    """Check the caller's explicit scratch contract before planning.

    Only ``MappingOrigin.VECTOR`` regions may be declared by a vector, and
    scratch is data-only: an ``EXECUTE`` request is refused rather than
    silently masking the bit, because executable caller memory would bypass
    the declared file/executable contract.
    """
    for region in vector.mappings:
        if region.origin is not MappingOrigin.VECTOR:
            raise ValueError("vector mappings must declare VECTOR scratch origin")
        if region.access & DeclaredAccess.EXECUTE:
            raise ValueError("vector scratch is data-only; EXECUTE is never granted")
    return vector.mappings


def _declared_regions(image: ReplayImage, vector: ReplayVector, stack: int) -> tuple[DeclaredRegion, ...]:
    """Assemble every typed declared region for one concrete guest.

    File regions come from the image's captured declarations, including
    explicit no-access denials; when none were captured the declared
    executable contract stands in as file-level read+execute. Loaded bytes
    without a declaration claim their pages as ``UNSUPPORTED`` so they stay
    mapped without access. Only the caller's explicit ``mappings`` scratch
    regions, the stack window and the return trap add harness roles;
    patches seed bytes and observations read bytes, and neither declares a
    region. Page resolution is owned by ``plan_page_grants``: file
    declarations bound shared pages.
    """
    file_regions = image.declared or tuple(
        DeclaredRegion(region.address, region.size, DeclaredAccess.READ | DeclaredAccess.EXECUTE, MappingOrigin.FILE)
        for region in image.executable
    )
    scratch = DeclaredAccess.READ | DeclaredAccess.WRITE
    return (
        *file_regions,
        *(
            DeclaredRegion(address, len(data), DeclaredAccess.NONE, MappingOrigin.UNSUPPORTED)
            for address, data in image.chunks
        ),
        *_vector_scratch(vector),
        DeclaredRegion(stack - PAGE_SIZE, PAGE_SIZE + 4, scratch, MappingOrigin.STACK),
        DeclaredRegion(RETURN_TRAP, 1, DeclaredAccess.EXECUTE, MappingOrigin.RETURN_TRAP),
    )


def _bind_guest_pages(
    guest: Uc, grants: tuple[PageGrant, ...], image: ReplayImage, vector: ReplayVector, stack: int
) -> None:
    """Map every granted page, seed declared bytes, then enforce access.

    Seeding uses the host-side write path before ``mem_protect`` applies the
    declared access, so a page granting no guest access still receives its
    initialized bytes without acquiring permissions.
    """
    for grant in grants:
        guest.mem_map(grant.address, PAGE_SIZE)
    for address, data in (*image.chunks, *vector.memory):
        guest.mem_write(address, data)
    guest.mem_write(stack, RETURN_TRAP.to_bytes(4, "little"))
    for grant in grants:
        if grant.access != DeclaredAccess(unicorn.UC_PROT_ALL):
            guest.mem_protect(grant.address, PAGE_SIZE, int(grant.access))


def _require_mapped_patches(vector: ReplayVector, grants: tuple[PageGrant, ...]) -> None:
    """Refuse a byte patch landing on any page without a declared mapping.

    Patches seed host bytes only; they must target pages a file image,
    unsupported loader backer, explicit scratch mapping, or harness role
    already declared. A patch reaching undeclared pages is a typed refusal
    instead of an implicitly manufactured mapping.
    """
    mapped = {grant.address for grant in grants}
    for address, data in vector.memory:
        if not data:
            continue
        first = address // PAGE_SIZE * PAGE_SIZE
        last = (address + len(data) - 1) // PAGE_SIZE * PAGE_SIZE
        if any(page not in mapped for page in range(first, last + PAGE_SIZE, PAGE_SIZE)):
            raise ValueError("memory patch is outside declared mapped memory")


def _check_ranges(vector: ReplayVector) -> None:
    """Bound metadata and aggregate byte work before mapping or reading it."""
    if max(len(vector.memory), len(vector.observations), len(vector.mappings)) > MAX_PAGE_CLAIMS:
        raise ValueError("flat32 replay vector metadata budget exhausted")
    patch_bytes = sum(len(data) for _, data in vector.memory)
    observation_bytes = sum(region.size for region in vector.observations)
    if max(patch_bytes, observation_bytes) > MAX_MAPPED_BYTES:
        raise ValueError("flat32 replay aggregate byte budget exhausted")
    if any(
        address < 0 or len(data) > MAX_MAPPED_BYTES or address + len(data) > 2**32 for address, data in vector.memory
    ):
        raise ValueError("memory patch is outside the flat32 budget")
    if any(
        region.size <= 0 or region.size > MAX_MAPPED_BYTES or region.address < 0 or region.address + region.size > 2**32
        for region in vector.observations
    ):
        raise ValueError("invalid flat32 observation range")


def _initialize_guest(
    image: ReplayImage, entry: int, vector: ReplayVector, instruction_limit: int
) -> tuple[Uc, tuple[PageGrant, ...]]:
    """Validate a concrete contract and create its fresh initialized guest.

    Pages are first mapped so declared bytes can be seeded, then protected
    to their resolved declared access. Seeding order never grants access:
    an ``UNSUPPORTED`` page keeps its loaded bytes but denies guest access.
    """
    values = dict(vector.registers)
    if len(values) != len(vector.registers) or set(values) - REGISTER_IDS.keys():
        raise ValueError("duplicate or unsupported flat32 input register")
    if instruction_limit <= 0 or not 4096 <= values.get("esp", 0) < RETURN_TRAP:
        raise ValueError("positive instruction budget and valid ESP are required")
    if not any(region.contains(entry) for region in image.executable):
        raise ValueError("entry is outside declared executable ranges")
    if any(address <= RETURN_TRAP < address + len(data) for address, data in image.chunks):
        raise ValueError("return trap overlaps loaded image")
    _check_ranges(vector)
    writes = (*vector.memory, (values["esp"], bytes(4)))
    if any(
        region.address < address + len(data) and address < region.address + region.size
        for address, data in writes
        for region in image.executable
    ):
        raise ValueError("initial memory patch overlaps executable bytes")
    stack = values["esp"]
    grants = plan_page_grants(_declared_regions(image, vector, stack))
    _require_mapped_patches(vector, grants)
    guest = make_guest(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    _bind_guest_pages(guest, grants, image, vector, stack)
    for name, identity in REGISTER_IDS.items():
        guest.reg_write(identity, values.get(name, 2 if name == "eflags" else 0))
    return guest, grants


def _capture_observation(guest: Uc, grant_by_page: dict[int, PageGrant], region: MemoryRange) -> MemoryObservation:
    """Read one requested range host-side when every page is declared mapped.

    Host reads reach mapped pages regardless of resolved guest access, so a
    protected FILE ``NONE`` or ``UNSUPPORTED`` page still yields its bytes
    with the denying provenance recorded. A range covering any undeclared
    page is an ``UNMAPPED`` non-result; the observation never creates or
    widens a mapping.
    """
    first = region.address // PAGE_SIZE * PAGE_SIZE
    last = (region.address + region.size - 1) // PAGE_SIZE * PAGE_SIZE
    covering = [grant_by_page[page] for page in range(first, last + PAGE_SIZE, PAGE_SIZE) if page in grant_by_page]
    origins = tuple(sorted({origin for grant in covering for origin in grant.origins}))
    if len(covering) * PAGE_SIZE != last - first + PAGE_SIZE:
        return MemoryObservation(region.address, region.size, ObservationStatus.UNMAPPED, b"", origins)
    data = bytes(guest.mem_read(region.address, region.size))
    return MemoryObservation(region.address, region.size, ObservationStatus.CAPTURED, data, origins)
