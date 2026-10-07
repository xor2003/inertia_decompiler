"""Build typed exact-instruction recovery coverage from frontend evidence.

Layer: Recovery/reporting.
Responsibility: classify exact instruction identity against CFG function
ownership without changing recovered control flow or validation policy.
Forbidden: semantic recovery, validation acceptance, postprocess ownership, or
text-pattern semantics.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.frontend.x86_16.cod_extract import CODProcMetadata
from inertia.frontend.x86_16.frontend_instruction_reachability import collect_instruction_reachability_8616

__all__ = [
    "ExactInstructionCoverageEvidence8616",
    "ExactInstructionCoverageSource8616",
    "ExactInstructionCoverageVerdict8616",
    "classify_exact_instruction_coverage_8616",
    "collect_exact_instruction_coverage_8616",
]


class ExactInstructionCoverageSource8616(StrEnum):
    """Frontend evidence source proving the expected instruction identity."""

    COD_EXACT_IMAGE = "cod_exact_image"


class ExactInstructionCoverageVerdict8616(StrEnum):
    """Recovery verdict for one exact instruction census."""

    COMPLETE = "complete"
    INCOMPLETE_REFUSE = "incomplete_refuse"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ExactInstructionCoverageEvidence8616:
    """Closed census comparing expected instructions with one CFG function."""

    function_addr: int | None
    source: ExactInstructionCoverageSource8616 | None
    verdict: ExactInstructionCoverageVerdict8616
    expected_instruction_addrs: tuple[int, ...] = ()
    recovered_instruction_addrs: tuple[int, ...] = ()
    missing_instruction_addrs: tuple[int, ...] = ()
    proven_unreachable_instruction_addrs: tuple[int, ...] = ()
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    excluded_unreachable_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every exact instruction belongs to the function."""
        return (
            self.verdict is ExactInstructionCoverageVerdict8616.COMPLETE
            and self.raw_fact_count > 0
            and self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count
            == self.materialized_count + self.excluded_unreachable_count + self.failure_count
            and self.failure_count == 0
            and not self.missing_instruction_addrs
        )

    def to_dict(self) -> dict[str, object]:
        """Return deterministic hard-failure and telemetry details."""
        return {
            "function_addr": self.function_addr,
            "source": self.source.value if self.source is not None else None,
            "verdict": self.verdict.value,
            "expected_instruction_addrs": self.expected_instruction_addrs,
            "recovered_instruction_addrs": self.recovered_instruction_addrs,
            "missing_instruction_addrs": self.missing_instruction_addrs,
            "proven_unreachable_instruction_addrs": self.proven_unreachable_instruction_addrs,
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "excluded_unreachable_count": self.excluded_unreachable_count,
            "failure_count": self.failure_count,
        }


class _InstructionBoundary8616(Protocol):
    """Instruction address exposed by the dynamic angr Capstone boundary."""

    address: object


class _CapstoneBoundary8616(Protocol):
    """Decoded instruction collection exposed by one angr block."""

    insns: object


class _BlockBoundary8616(Protocol):
    """Block fields consumed at the dynamic angr recovery boundary."""

    capstone: _CapstoneBoundary8616


class _FunctionBoundary8616(Protocol):
    """Function fields consumed at the dynamic angr recovery boundary."""

    addr: object
    blocks: object


class _MainObjectBoundary8616(Protocol):
    """Loaded-image bounds exposed by a dynamic CLE object."""

    min_addr: object
    max_addr: object


class _LoaderBoundary8616(Protocol):
    """Loader field consumed at the dynamic project boundary."""

    main_object: _MainObjectBoundary8616


class _ProjectBoundary8616(Protocol):
    """Project fields consumed while proving an exact loaded COD image."""

    loader: _LoaderBoundary8616


def classify_exact_instruction_coverage_8616(
    *,
    function_addr: int | None,
    source: ExactInstructionCoverageSource8616 | None,
    expected_instruction_addrs: Sequence[int],
    recovered_instruction_addrs: Sequence[int],
    proven_unreachable_instruction_addrs: Sequence[int] = (),
) -> ExactInstructionCoverageEvidence8616:
    """Classify exact instruction ownership with the required closed counters."""
    expected_raw = tuple(expected_instruction_addrs)
    expected = tuple(sorted(set(expected_raw)))
    recovered = tuple(sorted(set(recovered_instruction_addrs)))
    if source is None or not expected:
        return ExactInstructionCoverageEvidence8616(
            function_addr=function_addr,
            source=None,
            verdict=ExactInstructionCoverageVerdict8616.UNAVAILABLE,
            recovered_instruction_addrs=recovered,
        )
    recovered_set = set(recovered)
    proven_unreachable_set = set(proven_unreachable_instruction_addrs)
    proven_unreachable = tuple(
        addr for addr in expected if addr not in recovered_set and addr in proven_unreachable_set
    )
    missing = tuple(
        addr for addr in expected if addr not in recovered_set and addr not in proven_unreachable_set
    )
    materialized_count = len(expected) - len(missing) - len(proven_unreachable)
    verdict = (
        ExactInstructionCoverageVerdict8616.COMPLETE
        if not missing
        else ExactInstructionCoverageVerdict8616.INCOMPLETE_REFUSE
    )
    return ExactInstructionCoverageEvidence8616(
        function_addr=function_addr,
        source=source,
        verdict=verdict,
        expected_instruction_addrs=expected,
        recovered_instruction_addrs=recovered,
        missing_instruction_addrs=missing,
        proven_unreachable_instruction_addrs=proven_unreachable,
        raw_fact_count=len(expected_raw),
        normalized_fact_count=len(expected),
        classified_fact_count=len(expected),
        materialized_count=materialized_count,
        excluded_unreachable_count=len(proven_unreachable),
        failure_count=len(missing),
    )


def _recovered_instruction_addrs_8616(function: object) -> tuple[int, ...]:
    """Collect instruction starts from the dynamic angr function boundary."""
    boundary = cast(_FunctionBoundary8616, function)
    try:
        blocks = tuple(cast(Sequence[object], boundary.blocks) or ())
    except (AttributeError, TypeError):
        return ()
    recovered: set[int] = set()
    for block_value in blocks:
        block = cast(_BlockBoundary8616, block_value)
        try:
            instructions = tuple(cast(Sequence[object], block.capstone.insns) or ())
        except (AttributeError, TypeError):
            continue
        for instruction_value in instructions:
            instruction = cast(_InstructionBoundary8616, instruction_value)
            try:
                address = instruction.address
            except AttributeError:
                continue
            if isinstance(address, int):
                recovered.add(address)
    return tuple(sorted(recovered))


def _exact_loaded_cod_instruction_addrs_8616(
    project: object,
    function_addr: int | None,
    cod_metadata: CODProcMetadata | None,
) -> tuple[int, ...]:
    """Map COD rows only when they describe the complete loaded code image."""
    if cod_metadata is None or function_addr is None:
        return ()
    rows: list[tuple[int, int]] = []
    for entry in cod_metadata.cod_raw_entries:
        offset = entry.get("offset")
        data = entry.get("bytes")
        if not isinstance(offset, int) or not isinstance(data, bytes) or not data:
            return ()
        rows.append((offset, len(data)))
    if not rows:
        return ()
    first_offset = rows[0][0]
    expected_offset = first_offset
    for offset, size in rows:
        if offset != expected_offset:
            return ()
        expected_offset = offset + size
    project_boundary = cast(_ProjectBoundary8616, project)
    try:
        main_object = project_boundary.loader.main_object
        image_start = main_object.min_addr
        image_end_inclusive = main_object.max_addr
    except AttributeError:
        return ()
    image_size = (
        image_end_inclusive - image_start + 1
        if isinstance(image_start, int) and isinstance(image_end_inclusive, int)
        else None
    )
    cod_size = expected_offset - first_offset
    if image_size != cod_size or function_addr != image_start:
        return ()
    return tuple(image_start + offset - first_offset for offset, _size in rows)


def collect_exact_instruction_coverage_8616(
    project: object,
    function: object,
    cod_metadata: CODProcMetadata | None,
) -> ExactInstructionCoverageEvidence8616:
    """Collect exact loaded-image instruction coverage without repairing CFG."""
    boundary = cast(_FunctionBoundary8616, function)
    try:
        raw_function_addr = boundary.addr
    except AttributeError:
        raw_function_addr = None
    function_addr = raw_function_addr if isinstance(raw_function_addr, int) else None
    expected = _exact_loaded_cod_instruction_addrs_8616(project, function_addr, cod_metadata)
    source = ExactInstructionCoverageSource8616.COD_EXACT_IMAGE if expected else None
    proven_unreachable: tuple[int, ...] = ()
    if expected and function_addr is not None:
        project_boundary = cast(_ProjectBoundary8616, project)
        try:
            main_object = project_boundary.loader.main_object
            image_start = main_object.min_addr
            image_end_inclusive = main_object.max_addr
        except AttributeError:
            image_start = None
            image_end_inclusive = None
        if isinstance(image_start, int) and isinstance(image_end_inclusive, int):
            reachability = collect_instruction_reachability_8616(
                project,
                entry=function_addr,
                region_start=image_start,
                region_end=image_end_inclusive + 1,
            )
            if reachability.complete:
                reachable = set(reachability.reachable_instruction_addrs)
                proven_unreachable = tuple(addr for addr in expected if addr not in reachable)
    return classify_exact_instruction_coverage_8616(
        function_addr=function_addr,
        source=source,
        expected_instruction_addrs=expected,
        recovered_instruction_addrs=_recovered_instruction_addrs_8616(function),
        proven_unreachable_instruction_addrs=proven_unreachable,
    )
