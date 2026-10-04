"""Pure census controls for returning-service event verification.

Layer: Tests.
Responsibility: prove the executed-boundary census and receipt matching in
``symbolic_terminal_real16_services`` refuse every incomplete or forged
receipt list — removed-all, removed-one, duplicate, reorder, wrong site,
wrong payload, forged boundary encodings, missing declared selectors,
broken execution chains, outcome/site incoherence and counter-accounting
mismatches — while a legitimate repeated dispatch keeps one receipt per
occurrence. The census derives its denominator from the authenticated
block evidence and declared selectors, never from the supplied events.

These controls exercise the pure helper only — fabricated
``ServiceBlockEnding`` evidence plus a dict-backed byte reader. They never
build an ``ProgramEnvironment`` or touch the native lifter/proof chain, so
they use bounded native decoding without loading angr; the module must stay
free of the ``real16_program_boot`` import at runtime.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from dataclasses import replace

from tools.dosunit.proof_contracts import FactCounters
from tools.dosunit.real16_program_model import ProgramEventKind
from tools.dosunit.real16_program_version import (
    VersionPolicy,
    version_event_data,
)
from tools.dosunit.real16_program_video import (
    VideoQueryPolicy,
    video_query_event_data,
)
from tools.dosunit.real16_replay_model import SegOffset
from tools.dosunit.symbolic_terminal_real16_services import (
    ServiceBlockEnding,
    TerminalServiceEvent,
    returning_service_census,
    verify_returning_receipts,
)
from tools.dosunit.terminal_memory_effects import TerminalRefusal, TerminalRefusalKind

BASE = 0x10100
TERMINAL_TARGET = 0xFF000 + 0x21
VERSION_POLICY = VersionPolicy(3, 30, 0x42, 0x123456)
VIDEO_POLICY = VideoQueryPolicy(mode=3, columns=80, page=2, entry=SegOffset(0xF000, 0))

# mov ax,0x3000 ; int 21h ; mov ax,0x4C00 ; int 21h — one version query then exit.
QUERY_THEN_EXIT = bytes.fromhex("b80030cd21b8004ccd21")
QUERY_ENDINGS = (
    ServiceBlockEnding(BASE, 5, "Ijk_Call", BASE + 5),
    ServiceBlockEnding(BASE + 5, 5, "Ijk_Call", TERMINAL_TARGET),
)
QUERY_TERMINAL_SITE = BASE + 8

# Same query twice at distinct sites, then exit.
REPEATED_THEN_EXIT = bytes.fromhex("b80030cd21b80030cd21b8004ccd21")
REPEATED_ENDINGS = (
    ServiceBlockEnding(BASE, 5, "Ijk_Call", BASE + 5),
    ServiceBlockEnding(BASE + 5, 5, "Ijk_Call", BASE + 10),
    ServiceBlockEnding(BASE + 10, 5, "Ijk_Call", TERMINAL_TARGET),
)
REPEATED_TERMINAL_SITE = BASE + 13

# Version query, then video query, then exit.
ORDERED_THEN_EXIT = bytes.fromhex("b80030cd21b8000fcd10b8004ccd21")
ORDERED_ENDINGS = (
    ServiceBlockEnding(BASE, 5, "Ijk_Call", BASE + 5),
    ServiceBlockEnding(BASE + 5, 5, "Ijk_Call", BASE + 10),
    ServiceBlockEnding(BASE + 10, 5, "Ijk_Call", TERMINAL_TARGET),
)
ORDERED_TERMINAL_SITE = BASE + 13


def reader(image: bytes, base: int = BASE) -> Callable[[int, int], bytes | None]:
    """Resolve bytes from one fabricated contiguous image chunk."""

    def read(address: int, length: int) -> bytes | None:
        if base <= address and address + length <= base + len(image):
            return image[address - base : address - base + length]
        return None

    return read


def version_event(site: int) -> TerminalServiceEvent:
    """The receipt one executed version boundary must carry."""
    return TerminalServiceEvent(
        ProgramEventKind.DOS_VERSION, site, 0x21, 0x30,
        version_event_data(VERSION_POLICY),
    )


def video_event(site: int) -> TerminalServiceEvent:
    """The receipt one executed video boundary must carry."""
    return TerminalServiceEvent(
        ProgramEventKind.BIOS_VIDEO_QUERY, site, 0x10, 0x0F,
        video_query_event_data(VIDEO_POLICY),
    )


def counters(blocks: int, boundaries: int, outputs: int = 4) -> FactCounters:
    """The honest closed counters for a fabricated evidence set."""
    return FactCounters(
        raw_fact_count=blocks + boundaries,
        normalized_fact_count=blocks + boundaries,
        classified_fact_count=blocks + boundaries + 1,
        materialized_count=outputs + boundaries,
        failure_count=0,
    )


def verify(
    events: tuple[TerminalServiceEvent, ...],
    endings: tuple[ServiceBlockEnding, ...],
    image: bytes,
    *,
    version_policy: VersionPolicy | None = VERSION_POLICY,
    video_policy: VideoQueryPolicy | None = None,
    terminal_site: int | None = QUERY_TERMINAL_SITE,
    fault_outcome: bool = False,
    fact_counters: FactCounters | None = None,
    outputs: int = 4,
) -> TerminalRefusal | None:
    """One-call verification over fabricated native evidence."""
    return verify_returning_receipts(
        events,
        endings,
        reader(image),
        version_policy=version_policy,
        video_policy=video_policy,
        terminal_site=terminal_site,
        terminal_target=TERMINAL_TARGET if terminal_site is not None else None,
        fault_outcome=fault_outcome,
        outputs=outputs,
        counters=fact_counters
        if fact_counters is not None
        else counters(len(endings), len(events)),
    )


def stale(result: TerminalRefusal | None) -> None:
    """Assert one verification result is a typed stale-evidence refusal."""
    assert result is not None
    assert result.kind is TerminalRefusalKind.STALE_EVIDENCE


def test_module_stays_lifter_free() -> None:
    """The pure helper never pulls the native lifter chain at runtime."""
    result = subprocess.run(
        [sys.executable, "-c",
         "import sys; import tools.dosunit.symbolic_terminal_real16_services; "
         "assert \"pyvex\" not in sys.modules; assert \"angr\" not in sys.modules"],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_valid_single_receipt_verifies() -> None:
    """One executed boundary with its honest receipt verifies."""
    assert verify((version_event(BASE + 3),), QUERY_ENDINGS, QUERY_THEN_EXIT) is None


def test_removed_all_receipts_refuses() -> None:
    """An empty event list cannot hide an executed boundary."""
    stale(verify((), QUERY_ENDINGS, QUERY_THEN_EXIT))


def test_retagged_call_cannot_hide_executed_service() -> None:
    """Changing receipt metadata cannot erase a native INT from the census."""
    endings = (replace(QUERY_ENDINGS[0], jumpkind="Ijk_Boring"), QUERY_ENDINGS[1])
    stale(verify((), endings, QUERY_THEN_EXIT))


def test_immediate_bytes_are_not_an_interrupt() -> None:
    """MOV AX,21CDh contains CD21 bytes but executes no service."""
    image = bytes.fromhex("b8cd21b8004ccd21")
    endings = (
        ServiceBlockEnding(BASE, 3, "Ijk_Boring", BASE + 3),
        ServiceBlockEnding(BASE + 3, 5, "Ijk_Call", TERMINAL_TARGET),
    )
    assert verify((), endings, image, terminal_site=BASE + 6) is None
    forged = (replace(endings[0], jumpkind="Ijk_Call"), endings[1])
    stale(verify((version_event(BASE + 1),), forged, image, terminal_site=BASE + 6))


def test_merged_blocks_cannot_hide_earlier_interrupt() -> None:
    """A forged enlarged final block cannot swallow an earlier native query."""
    endings = (ServiceBlockEnding(BASE, len(QUERY_THEN_EXIT), "Ijk_Call", TERMINAL_TARGET),)
    stale(verify((), endings, QUERY_THEN_EXIT))


def test_forged_fallthrough_cannot_skip_native_service() -> None:
    """Truncating a block before INT cannot invent a jump past the service."""
    endings = (
        ServiceBlockEnding(BASE, 3, "Ijk_Boring", BASE + 5),
        QUERY_ENDINGS[1],
    )
    stale(verify((), endings, QUERY_THEN_EXIT))


def test_removed_one_receipt_refuses() -> None:
    """Dropping one of two receipts shrinks the count below the census."""
    events = (version_event(BASE + 3),)
    stale(verify(events, REPEATED_ENDINGS, REPEATED_THEN_EXIT, terminal_site=REPEATED_TERMINAL_SITE))


def test_duplicate_receipt_refuses() -> None:
    """A duplicated receipt cannot reuse one boundary's answer."""
    event = version_event(BASE + 3)
    stale(verify((event, event), QUERY_ENDINGS, QUERY_THEN_EXIT))


def test_duplicate_over_two_boundaries_refuses() -> None:
    """Repeating the first receipt cannot answer the second boundary."""
    events = (version_event(BASE + 3), version_event(BASE + 3))
    stale(verify(events, REPEATED_ENDINGS, REPEATED_THEN_EXIT, terminal_site=REPEATED_TERMINAL_SITE))


def test_reordered_receipts_refuse() -> None:
    """Swapped version/video receipts mismatch the positional census."""
    events = (video_event(BASE + 8), version_event(BASE + 3))
    stale(
        verify(
            events,
            ORDERED_ENDINGS,
            ORDERED_THEN_EXIT,
            video_policy=VIDEO_POLICY,
            terminal_site=ORDERED_TERMINAL_SITE,
        )
    )


def test_wrong_site_refuses() -> None:
    """A receipt bound to the wrong native site refuses."""
    stale(verify((version_event(BASE + 4),), QUERY_ENDINGS, QUERY_THEN_EXIT))


def test_wrong_payload_refuses() -> None:
    """A receipt whose payload does not re-derive refuses."""
    forged = replace(version_event(BASE + 3), data=b"\x00" * 8)
    stale(verify((forged,), QUERY_ENDINGS, QUERY_THEN_EXIT))


def test_wrong_function_refuses() -> None:
    """A receipt carrying a different declared selector refuses."""
    forged = replace(version_event(BASE + 3), function=0x4C)
    stale(verify((forged,), QUERY_ENDINGS, QUERY_THEN_EXIT))


def test_extra_receipt_refuses() -> None:
    """An extra receipt beyond the census refuses."""
    events = (version_event(BASE + 3), version_event(BASE + 8))
    stale(verify(events, QUERY_ENDINGS, QUERY_THEN_EXIT))


def test_valid_repeated_occurrences_verify() -> None:
    """Two honest receipts for two executed queries verify."""
    events = (version_event(BASE + 3), version_event(BASE + 8))
    assert (
        verify(events, REPEATED_ENDINGS, REPEATED_THEN_EXIT, terminal_site=REPEATED_TERMINAL_SITE) is None
    )


def test_valid_ordered_mixed_boundaries_verify() -> None:
    """Version-then-video receipts in census order verify."""
    events = (version_event(BASE + 3), video_event(BASE + 8))
    assert (
        verify(
            events,
            ORDERED_ENDINGS,
            ORDERED_THEN_EXIT,
            video_policy=VIDEO_POLICY,
            terminal_site=ORDERED_TERMINAL_SITE,
        )
        is None
    )


def test_census_derives_boundaries_from_block_evidence() -> None:
    """The census itself names every executed returning boundary in order."""
    census = returning_service_census(
        REPEATED_ENDINGS,
        reader(REPEATED_THEN_EXIT),
        version_policy=VERSION_POLICY,
        video_policy=None,
        terminal_site=REPEATED_TERMINAL_SITE,
        terminal_target=TERMINAL_TARGET,
        fault_outcome=False,
    )
    assert isinstance(census, tuple)
    assert [b.site for b in census] == [BASE + 3, BASE + 8]
    assert all(b.kind is ProgramEventKind.DOS_VERSION for b in census)


def test_forged_call_block_without_cd_refuses() -> None:
    """An Ijk_Call receipt whose bytes do not end in CD imm8 refuses."""
    endings = (
        ServiceBlockEnding(BASE, 5, "Ijk_Call", BASE + 5),
        QUERY_ENDINGS[1],
    )
    image = bytes.fromhex("b800309090b8004ccd21")
    stale(verify((version_event(BASE + 3),), endings, image))


def test_undeclared_vector_boundary_refuses() -> None:
    """A middle CD 03 boundary has no declared dispatch — forged evidence."""
    endings = (
        ServiceBlockEnding(BASE, 5, "Ijk_Call", BASE + 5),
        ServiceBlockEnding(BASE + 5, 5, "Ijk_Call", BASE + 10),
        ServiceBlockEnding(BASE + 10, 5, "Ijk_Call", TERMINAL_TARGET),
    )
    image = bytes.fromhex("b80030cd03b80030cd21b8004ccd21")
    events = (version_event(BASE + 8),)
    stale(verify(events, endings, image, terminal_site=BASE + 13))


def test_undeclared_selector_int21_refuses() -> None:
    """A middle CD 21 with no version policy has no declared returning call."""
    stale(
        verify(
            (),
            QUERY_ENDINGS,
            QUERY_THEN_EXIT,
            version_policy=None,
        )
    )


def test_undeclared_video_boundary_refuses() -> None:
    """A middle CD 10 with no video policy has no declared returning call."""
    endings = (
        ServiceBlockEnding(BASE, 5, "Ijk_Call", BASE + 5),
        ServiceBlockEnding(BASE + 5, 5, "Ijk_Call", BASE + 10),
        ServiceBlockEnding(BASE + 10, 5, "Ijk_Call", TERMINAL_TARGET),
    )
    events = (version_event(BASE + 3), video_event(BASE + 8))
    stale(
        verify(
            events,
            endings,
            ORDERED_THEN_EXIT,
            terminal_site=ORDERED_TERMINAL_SITE,
        )
    )


def test_terminal_site_mismatch_refuses() -> None:
    """A declared terminal site not bound by the closing block refuses."""
    stale(
        verify(
            (version_event(BASE + 3),),
            QUERY_ENDINGS,
            QUERY_THEN_EXIT,
            terminal_site=BASE + 4,
        )
    )


def test_missing_terminal_boundary_refuses() -> None:
    """A declared-service outcome without a closing CD21 block refuses."""
    endings = (ServiceBlockEnding(BASE, 5, "Ijk_Boring", BASE + 5),)
    stale(
        verify(
            (),
            endings,
            QUERY_THEN_EXIT,
            terminal_site=BASE + 8,
        )
    )


def test_broken_successor_chain_refuses() -> None:
    """A block whose next_target skips its recorded successor refuses."""
    endings = (
        ServiceBlockEnding(BASE, 5, "Ijk_Call", BASE + 7),
        QUERY_ENDINGS[1],
    )
    stale(verify((version_event(BASE + 3),), endings, QUERY_THEN_EXIT))


def test_fallthrough_mismatch_refuses() -> None:
    """A returning boundary whose next_target is not site+2 refuses."""
    endings = (
        ServiceBlockEnding(BASE, 7, "Ijk_Call", BASE + 7),
        ServiceBlockEnding(BASE + 7, 5, "Ijk_Call", TERMINAL_TARGET),
    )
    image = bytes.fromhex("b80030cd210000b8004ccd21")
    stale(verify((version_event(BASE + 5),), endings, image, terminal_site=BASE + 10))


def test_non_admitted_middle_jumpkind_refuses() -> None:
    """A middle block claiming a signal jumpkind is forged evidence."""
    endings = (
        ServiceBlockEnding(BASE, 5, "Ijk_SigTRAP", BASE + 5),
        QUERY_ENDINGS[1],
    )
    stale(verify((), endings, QUERY_THEN_EXIT))


def test_counter_mismatch_refuses() -> None:
    """Counters that do not re-derive from the evidence census refuse."""
    forged = FactCounters(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=2,
        materialized_count=1,
        failure_count=0,
    )
    stale(
        verify(
            (version_event(BASE + 3),),
            QUERY_ENDINGS,
            QUERY_THEN_EXIT,
            fact_counters=forged,
        )
    )


def test_failure_count_refuses() -> None:
    """A nonzero failure count cannot hide dropped evidence work."""
    forged = replace(
        counters(len(QUERY_ENDINGS), 1), failure_count=1
    )
    stale(
        verify(
            (version_event(BASE + 3),),
            QUERY_ENDINGS,
            QUERY_THEN_EXIT,
            fact_counters=forged,
        )
    )


def test_fault_boundary_skips_receipts() -> None:
    """A prefix fault on the closing INT block needs no service receipt."""
    endings = (
        ServiceBlockEnding(BASE, 5, "Ijk_Call", BASE + 5),
        ServiceBlockEnding(BASE + 5, 5, "Ijk_Call", None),
    )
    assert (
        verify(
            (version_event(BASE + 3),),
            endings,
            QUERY_THEN_EXIT,
            terminal_site=None,
            fault_outcome=True,
        )
        is None
    )


def test_fault_boundary_with_successor_refuses() -> None:
    """A fault boundary claiming a successor is forged evidence."""
    endings = (
        ServiceBlockEnding(BASE, 5, "Ijk_Call", BASE + 5),
        ServiceBlockEnding(BASE + 5, 5, "Ijk_Call", BASE + 10),
    )
    stale(
        verify(
            (version_event(BASE + 3),),
            endings,
            QUERY_THEN_EXIT,
            terminal_site=None,
            fault_outcome=True,
        )
    )
