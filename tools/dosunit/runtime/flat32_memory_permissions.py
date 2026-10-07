"""Declared page-level access resolution for flat32 concrete replay.

Layer: dosunit concrete execution.
Responsibility: combine typed declared regions into one deterministic
per-page access plan. Image/file declarations bound harness roles on shared
pages; caller scratch, stack and return-trap roles apply only where no file
declaration covers the page; loaded bytes without any declaration stay
mapped without access instead of inventing operating-system permissions.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntFlag, StrEnum

import unicorn

PAGE_SIZE: int = 4096
MAX_MAPPED_BYTES: int = 64 * 1024 * 1024
MAX_MAPPED_PAGES: int = MAX_MAPPED_BYTES // PAGE_SIZE
MAX_PAGE_CLAIMS: int = 4 * MAX_MAPPED_PAGES
"""Finite declaration work, allowing overlaps without multiplying it forever."""


class DeclaredAccess(IntFlag):
    """File or harness declared access; bit values match UC_PROT_*."""

    NONE = 0
    READ = unicorn.UC_PROT_READ
    WRITE = unicorn.UC_PROT_WRITE
    EXECUTE = unicorn.UC_PROT_EXEC


class MappingOrigin(StrEnum):
    """Who declared a mapped byte range; never recovered from rendered text."""

    FILE = "file"
    """Main-image declared access (ELF PT_LOAD flags, PE section traits),
    including explicit no-access denials."""
    VECTOR = "vector"
    """Caller-declared scratch mapping; bounded by file coverage. Only an
    explicit ``ReplayVector.mappings`` region carries this origin; byte
    patches and observations never manufacture scratch."""
    STACK = "stack"
    """Harness-declared single stack page window below the declared ESP."""
    RETURN_TRAP = "return_trap"
    """Harness-declared trap page; executable so the code hook can stop."""
    PROCESS_SERVICE = "process_service"
    """Explicit whole-program environment gateway; never a function return trap."""
    UNSUPPORTED = "unsupported"
    """Loaded bytes with no file declaration (CLE synthetic objects, headers
    or other unannotated backers). Mapped without access; never widened."""


@dataclass(frozen=True, slots=True)
class DeclaredRegion:
    """One byte range with its declared access and typed origin."""

    address: int
    size: int
    access: DeclaredAccess
    origin: MappingOrigin


@dataclass(frozen=True, slots=True)
class PageGrant:
    """One mapped page: resolved access plus every covering origin.

    ``origins`` is the typed evidence of which declarations covered the
    page; ``access`` is what the guest may actually do on it.
    """

    address: int
    access: DeclaredAccess
    origins: tuple[MappingOrigin, ...]


def _region_pages(region: DeclaredRegion) -> range:
    """Enumerate pages a valid region covers without address wrapping."""
    if region.size <= 0 or region.address < 0 or region.address + region.size > 2**32:
        raise ValueError("invalid flat32 replay memory range")
    if region.size > MAX_MAPPED_BYTES:
        raise ValueError("flat32 replay range exceeds 64 MiB budget")
    first = region.address // PAGE_SIZE * PAGE_SIZE
    last = (region.address + region.size - 1) // PAGE_SIZE * PAGE_SIZE
    return range(first, last + PAGE_SIZE, PAGE_SIZE)


def _claim_pages(regions: Iterable[DeclaredRegion]) -> dict[int, list[DeclaredRegion]]:
    """Collect per-page covering regions under the bounded intake contract.

    Validation and the 64 MiB budget bound each region before its pages are
    claimed. Distinct pages and total page claims have separate finite
    budgets, so repeated overlapping declarations cannot bypass work bounds.
    """
    claims: dict[int, list[DeclaredRegion]] = {}
    work = 0
    for region in regions:
        pages = _region_pages(region)
        work += len(pages)
        if work > MAX_PAGE_CLAIMS:
            raise ValueError("flat32 replay page-claim work budget exhausted")
        for page in pages:
            if page not in claims:
                if len(claims) >= MAX_MAPPED_PAGES:
                    raise ValueError("flat32 replay mappings exceed 64 MiB budget")
                claims[page] = []
            claims[page].append(region)
    return claims


def plan_page_grants(regions: Iterable[DeclaredRegion]) -> tuple[PageGrant, ...]:
    """Resolve declared regions into a deterministic page grant plan.

    Policy, applied per page in declared linear-address order:

    - A page covered by any ``FILE`` region receives the union of the file
      accesses covering it. Harness roles never widen file-declared pages,
      and a file ``NONE`` declaration is an explicit denial resolving the
      page to no guest access.
    - A page with no file coverage receives the union of its declared
      harness accesses (``VECTOR``/``STACK``/``RETURN_TRAP``/``PROCESS_SERVICE``).
    - ``UNSUPPORTED`` coverage claims the page but grants no access, so
      bytes loaded without declared permissions stay mapped but denied.

    Intake is bounded before unbounded per-page claim allocation:
    ``_claim_pages`` validates each region, caps it at the 64 MiB budget
    and refuses distinct pages past ``MAX_MAPPED_PAGES`` or total claims
    past ``MAX_PAGE_CLAIMS`` before allocating their covering records.
    """
    claims = _claim_pages(regions)
    grants: list[PageGrant] = []
    for page in sorted(claims):
        covering = claims[page]
        file_regions = [region for region in covering if region.origin is MappingOrigin.FILE]
        if file_regions:
            resolved = DeclaredAccess.NONE
            for region in file_regions:
                resolved |= region.access
        else:
            resolved = DeclaredAccess.NONE
            for region in covering:
                resolved |= region.access
        origins = tuple(sorted({region.origin for region in covering}))
        grants.append(PageGrant(page, resolved, origins))
    return tuple(grants)
