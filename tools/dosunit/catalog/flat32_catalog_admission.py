"""Layer: dosunit catalog admission.

Responsibility: verify flat32 function entries and declared byte extents against
the loaded image's executable sections before decoding. An admitted range is
only a byte envelope; complete reachable control flow still needs its own proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from cle.backends.pe import PE

if TYPE_CHECKING:
    import angr


class CatalogRangeStatus(StrEnum):
    """Outcome of verifying an entry and its optional declared byte extent."""

    ADMITTED = "admitted"
    INVALID_EXTENT = "invalid_function_extent"
    ENTRY_OUTSIDE_CODE = "entry_outside_executable_section"
    EXTENT_OUTSIDE_CODE = "extent_outside_executable_sections"


class CatalogSide(StrEnum):
    """Image whose declaration lacks executable-section evidence."""

    ORACLE = "oracle"
    CANDIDATE = "candidate"


@dataclass(frozen=True)
class CatalogAdmissionFailure:
    """A typed pair-admission rejection bound to its offending image."""

    side: CatalogSide
    evidence: CatalogRangeEvidence

    def to_document(self) -> dict[str, object]:
        """Serialize the side and loaded executable-range evidence together."""
        return {"side": self.side.value, **self.evidence.to_document()}


@dataclass(frozen=True)
class CatalogRangeEvidence:
    """Loaded-section evidence for one function declaration, not a CFG proof."""

    status: CatalogRangeStatus
    entry: int
    size: int
    executable_ranges: tuple[tuple[int, int], ...]

    def to_document(self) -> dict[str, object]:
        """Retain typed rejection evidence in the function's compare report."""
        return {
            "status": self.status.value,
            "entry": self.entry,
            "declared_size": self.size,
            "executable_ranges": [list(span) for span in self.executable_ranges],
        }


def check_function_extent(
    project: angr.Project, *, entry: int, size: int,
) -> CatalogRangeEvidence:
    """Admit bytes only inside executable sections of the main loaded image.

    Size zero means an unknown extent: only the entry is admitted, and the
    scanner remains responsible for every subsequently reached byte. Positive
    sizes are exact half-open envelopes, including contiguous code sections but
    excluding unmapped gaps, non-code sections and 32-bit address overflow.
    """
    spans = sorted(
        (section.min_addr, section.max_addr + 1)
        for section in project.loader.main_object.sections
        if section.is_executable and section.max_addr >= section.min_addr
    )
    merged: list[tuple[int, int]] = []
    for left, right in spans:
        if merged and left <= merged[-1][1]:
            merged[-1] = merged[-1][0], max(right, merged[-1][1])
        else:
            merged.append((left, right))
    ranges = tuple(merged)
    if (type(entry) is not int or type(size) is not int or not 0 <= entry <= 0xFFFFFFFF
            or size < 0 or entry + size > 0x100000000):
        return CatalogRangeEvidence(CatalogRangeStatus.INVALID_EXTENT, entry, size, ranges)
    for left, right in ranges:
        if left <= entry < right:
            status = (CatalogRangeStatus.ADMITTED if size == 0 or entry + size <= right
                      else CatalogRangeStatus.EXTENT_OUTSIDE_CODE)
            return CatalogRangeEvidence(status, entry, size, ranges)
    return CatalogRangeEvidence(CatalogRangeStatus.ENTRY_OUTSIDE_CODE, entry, size, ranges)


def check_declared_pair(
    oracle: angr.Project, candidate: angr.Project, *, oracle_entry: int,
    oracle_end_byte: int, candidate_entry: int, candidate_size: int,
) -> CatalogAdmissionFailure | None:
    """Check PE32 declarations before decoding their instruction-head bounds.

    An oracle listing initially gives an inclusive last instruction head, so
    its preliminary envelope ends at that byte. The caller checks the extended
    envelope again once the final instruction's decoded width is known.
    Other loader formats retain their existing intake contracts; this check
    adds no section-policy requirements to the preserved ELF or blob paths.
    """
    for side, project, entry, size in (
        (CatalogSide.ORACLE, oracle, oracle_entry, oracle_end_byte - oracle_entry + 1),
        (CatalogSide.CANDIDATE, candidate, candidate_entry, candidate_size),
    ):
        if not isinstance(project.loader.main_object, PE):
            continue
        evidence = check_function_extent(project, entry=entry, size=size)
        if evidence.status is not CatalogRangeStatus.ADMITTED:
            return CatalogAdmissionFailure(side, evidence)
    return None
