"""Consume a bound entry-domain proof into converted AIL terminal jumps.

Layer: Frontend/runtime.
Responsibility: at the Clinic whole-function conversion boundary, bind the
entry-domain-discharged loader-linear targets onto the exact AIL ``Jump``
terminals that still carry this block's symbolic ``next`` operand. The
per-block all-selector transport already ran during conversion; this stage
consumes only the separate ``EntryJumpTransportProof8616`` produced over
the same recovered function surface — never a serialized summary and never
a fabricated per-block evidence record. Only unconditional admissions are
transported: a record that retains an invocation premise, an invocation
scope, or call dependencies keeps the symbolic operand under a typed
refusal, as does any missing admission, stale source bytes, census
mismatch, or binding failure. Execution VEX is never mutated and the
per-block stronger-theorem reports are left untouched — the prior
selector-dependent refusal stays on record rather than being rewritten as
if the per-instruction theorem had passed. One bounded proof runs per
Clinic conversion, with fresh context checks before and after the proof.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, cast

import pyvex
from angr import ailment

from inertia.ir.entry_jump_domain import (
    AdmittedTerminalJump8616,
    PendingTerminalJump8616,
)
from inertia.ir.vex_terminal_jump import TerminalJumpRefusalReason8616

if TYPE_CHECKING:
    from inertia.ir.entry_jump_transport import EntryJumpTransportProof8616

    from .clinic_scoped_control import ClinicScopedPartition8616

from .clinic_conversion_source import (
    ClinicAilSnapshot8616,
    ClinicConversionContext8616,
    ClinicVexSnapshot8616,
    clinic_context_is_current_8616,
    clinic_converted_object_8616,
    clinic_source_bytes_8616,
    snapshot_clinic_ail_8616,
    snapshot_clinic_context_8616,
    snapshot_clinic_vex_8616,
)
from .clinic_terminal_control import (
    ClinicTerminalControlRefusal8616,
    ClinicTerminalControlStats8616,
    ClinicTerminalTransport8616,
    rebind_terminal_jump_8616,
)

__all__ = (
    "CLINIC_ENTRY_JUMP_CAPTURES_ATTR_8616",
    "CLINIC_ENTRY_JUMP_TRANSPORT_ATTR_8616",
    "ClinicConvertedBlockCapture8616",
    "ClinicEntryJumpDecision8616",
    "ClinicEntryJumpTransport8616",
    "ClinicEntryJumpTransportRefusal8616",
    "ClinicEntryJumpTransportStatus8616",
    "begin_clinic_entry_jump_conversion_8616",
    "capture_clinic_converted_block_8616",
    "record_clinic_entry_jump_transport_8616",
    "transport_clinic_entry_jumps_8616",
)

# Typed ledgers stashed on the third-party Clinic instance: the converted
# block captures accumulated during ``_convert_vex`` and the whole-function
# transport reports appended after conversion. Dynamic attributes belong to
# the angr boundary; this module owns only their contents.
CLINIC_ENTRY_JUMP_CAPTURES_ATTR_8616: str = "_inertia_entry_jump_captures_8616"
CLINIC_ENTRY_JUMP_TRANSPORT_ATTR_8616: str = "_inertia_entry_jump_transports_8616"
_CONTEXT_ATTR_8616 = "_inertia_entry_jump_conversion_context_8616"


class ClinicEntryJumpTransportRefusal8616(StrEnum):
    """Typed reason the entry-domain transport kept a symbolic operand."""

    FOREIGN_PRODUCT = "clinic_entry_jump_foreign_product"
    PROOF_REFUSED = "clinic_entry_jump_proof_refused"
    BLOCK_CENSUS_MISMATCH = "clinic_entry_jump_block_census_mismatch"
    ADMISSION_MISSING = "clinic_entry_jump_admission_missing"
    ADMISSION_SCOPE_UNSUPPORTED = "clinic_entry_jump_admission_scope_unsupported"
    SOURCE_RELIFT_FAILED = "clinic_entry_jump_source_relift_failed"
    CONTEXT_STALE = "clinic_entry_jump_context_stale"
    SOURCE_BYTES_STALE = "clinic_entry_jump_source_bytes_stale"
    SOURCE_EXTENT_MISMATCH = "clinic_entry_jump_source_extent_mismatch"
    TERMINAL_ENCODING_MISMATCH = "clinic_entry_jump_terminal_encoding_mismatch"


class ClinicEntryJumpTransportStatus8616(StrEnum):
    """Whole-function outcome of one entry-domain transport pass."""

    EMPTY = "empty"
    TRANSPORTED = "transported"
    PARTIAL = "partial"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class ClinicConvertedBlockCapture8616:
    """One converted (native block -> AIL block) pair with a source snapshot.

    ``block`` and ``vex`` retain the exact third-party objects the
    conversion consumed; ``converted`` is the AIL block object the
    whole-function pass may rebind; ``source_bytes`` is an immutable
    snapshot of the mapped native bytes taken at conversion time and
    rechecked against a fresh bounded relift before any operand is touched.
    """

    block: object = field(compare=False)
    converted: object = field(compare=False)
    vex: object = field(compare=False)
    addr: int
    size: int
    source_bytes: bytes
    execution: ClinicVexSnapshot8616
    ail: ClinicAilSnapshot8616
    pending: bool


@dataclass(frozen=True, slots=True)
class ClinicEntryJumpDecision8616:
    """One pending candidate's terminal transport decision.

    ``applied`` is True only when the block's own terminal operand was
    re-pointed at ``target`` under the admitted entry-domain record;
    ``refusal`` is the typed reason the symbolic operand stayed — either a
    transport refusal from this owner or a shared binding refusal.
    """

    block_addr: int
    head: int
    applied: bool
    target: int | None
    refusal: (
        ClinicTerminalControlRefusal8616
        | ClinicEntryJumpTransportRefusal8616
        | None
    )
    detail: str

    def to_dict(self) -> dict[str, object]:
        """Serialize the decision for diagnostics and workers."""
        return {
            "block_addr": self.block_addr,
            "head": self.head,
            "applied": self.applied,
            "target": self.target,
            "refusal": None if self.refusal is None else self.refusal.value,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ClinicEntryJumpTransport8616:
    """Whole-function entry-domain transport report.

    ``proof`` retains the bound IR proof product this pass consumed —
    including its domain proof, application, and source binding — so the
    decision record never erases the reason the per-block theorem stayed
    unproved. ``decisions`` keeps one typed outcome per pending candidate.
    ``stats`` closes over the converted-block census, the pending
    candidates, and materialization/refusal counts.
    """

    status: ClinicEntryJumpTransportStatus8616
    proof: EntryJumpTransportProof8616 | None = field(compare=False)
    decisions: tuple[ClinicEntryJumpDecision8616, ...] = ()
    stats: ClinicTerminalControlStats8616 = field(
        default_factory=lambda: ClinicTerminalControlStats8616(0, 0, 0, 0, 0)
    )
    detail: str = ""
    refusal: ClinicEntryJumpTransportRefusal8616 | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize the report for diagnostics and workers."""
        return {
            "status": self.status.value,
            "refusal": None if self.refusal is None else self.refusal.value,
            "detail": self.detail,
            "stats": self.stats.to_dict(),
            "decisions": [decision.to_dict() for decision in self.decisions],
            "proof": None if self.proof is None else self.proof.to_dict(),
        }


def begin_clinic_entry_jump_conversion_8616(clinic: object) -> None:
    """Start a fresh conversion with one immutable native control snapshot."""
    from .clinic_scoped_control import prepare_clinic_universal_partition_8616

    prepare_clinic_universal_partition_8616(clinic)
    # Dynamic boundary: these ledgers attach to third-party angr Clinic.
    setattr(clinic, CLINIC_ENTRY_JUMP_CAPTURES_ATTR_8616, {})
    # Dynamic boundary: context attaches to third-party angr Clinic.
    setattr(clinic, _CONTEXT_ATTR_8616, snapshot_clinic_context_8616(clinic))


def _context_is_current_8616(
    clinic: object, captures: Mapping[tuple[int, int], ClinicConvertedBlockCapture8616],
    *, scoped_partition: ClinicScopedPartition8616 | None = None,
) -> bool:
    """Authenticate every context block, not just the jump instruction."""
    # Dynamic boundary: the context is optional on third-party angr Clinic.
    context = getattr(clinic, _CONTEXT_ATTR_8616, None)
    if not isinstance(context, ClinicConversionContext8616):
        return False
    if scoped_partition is None:
        from inertia.ir.entry_jump_transport import EntryJumpTransportProof8616

        from .clinic_scoped_control import ClinicScopedPartition8616

        # Dynamic third-party boundary: universal partition has no declared entry.
        retained = getattr(clinic, "_inertia_clinic_scoped_partition_8616", None)
        if (retained is not None and type(retained) is ClinicScopedPartition8616
                and type(retained.entry) is EntryJumpTransportProof8616):
            scoped_partition = retained
    if not clinic_context_is_current_8616(clinic, context, scoped_partition=scoped_partition):
        return False
    if tuple(sorted(captures)) != context.graph.nodes:
        return False
    for (addr, size), record in captures.items():
        block = cast(_BlockBytesBoundary8616, record.block)
        identity_matches = (
            (addr, size) == (record.addr, record.size)
            and block.addr == addr and block.size == size
            and record.vex is block.vex
            and clinic_converted_object_8616(clinic, addr, size) is record.converted
        )
        execution_matches = (
            record.execution.matches(record.vex)
            and record.ail.matches(record.converted)
            and len(record.source_bytes) == size
            and clinic_source_bytes_8616(clinic, addr, size) == record.source_bytes
        )
        if not identity_matches or not execution_matches:
            return False
    return True


def capture_clinic_converted_block_8616(
    clinic: object, block: object, converted: object,
    *, transport: ClinicTerminalTransport8616,
) -> None:
    """Retain one converted (native block -> AIL block) pair for the pass.

    Called once per ``_convert_vex`` at the same wrapper boundary as the
    per-block terminal transport. Non-AIL conversions contribute nothing.
    A re-conversion of the same ``(addr, size)`` node replaces the stale
    record so the pass always binds the latest AIL object.
    """
    if not isinstance(converted, ailment.Block):
        return
    block_boundary = cast("_BlockBytesBoundary8616", block)
    # Dynamic boundary: conversion captures attach to third-party angr Clinic.
    captures = getattr(clinic, CLINIC_ENTRY_JUMP_CAPTURES_ATTR_8616, None)
    if captures is None:
        captures = {}
        # Dynamic boundary: initialize the third-party angr Clinic ledger.
        setattr(clinic, CLINIC_ENTRY_JUMP_CAPTURES_ATTR_8616, captures)
    addr = int(block_boundary.addr)
    size = int(block_boundary.size)
    vex = block_boundary.vex
    captures[(addr, size)] = ClinicConvertedBlockCapture8616(
        block=block,
        converted=converted,
        vex=vex,
        addr=addr,
        size=size,
        source_bytes=bytes(block_boundary.bytes),
        execution=snapshot_clinic_vex_8616(cast(pyvex.IRSB, vex)),
        ail=snapshot_clinic_ail_8616(converted, cast(pyvex.IRSB, vex).arch.ip_offset),
        pending=(transport.evidence is not None and transport.evidence.failure
                 is TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED),
    )


class _BlockBytesBoundary8616(Protocol):
    """Structural surface of the angr block the capture consumes."""

    addr: int
    size: int
    bytes: bytes
    vex: object


def _pending_transport_reports_8616(clinic: object) -> int:
    """Count converted blocks whose retained terminal stayed window-bound."""
    return sum(int(record.pending) for record in _captures_8616(clinic).values())


def _captures_8616(
    clinic: object,
) -> dict[tuple[int, int], ClinicConvertedBlockCapture8616]:
    """Return the conversion-time capture ledger, or an empty map."""
    # Dynamic boundary: conversion captures attach to third-party angr Clinic.
    captures = getattr(clinic, CLINIC_ENTRY_JUMP_CAPTURES_ATTR_8616, None)
    if not isinstance(captures, dict):
        return {}
    return captures


def _decision_8616(
    candidate: PendingTerminalJump8616,
    *,
    applied: bool = False,
    target: int | None = None,
    refusal: (
        ClinicTerminalControlRefusal8616
        | ClinicEntryJumpTransportRefusal8616
        | None
    ) = None,
    detail: str = "",
) -> ClinicEntryJumpDecision8616:
    """Close one candidate decision over the consumed pending record."""
    return ClinicEntryJumpDecision8616(
        block_addr=candidate.block_addr,
        head=candidate.decoded.head,
        applied=applied,
        target=target,
        refusal=refusal,
        detail=detail,
    )


def _refusal_for_candidate_8616(
    product: EntryJumpTransportProof8616, block_addr: int,
) -> str:
    """Return the domain proof's own refusal detail for one block, if any."""
    proof = product.proof
    if proof is not None:
        for refusal in proof.refusals:
            if refusal.block_addr == block_addr:
                return refusal.detail
    return "entry-domain proof retained this candidate's default refusal"


def _unconditional_8616(jump: AdmittedTerminalJump8616) -> bool:
    """Accept only admissions discharged by the joint-window theorem alone."""
    return (
        jump.invocation is None
        and jump.invocation_scope is None
        and not jump.call_dependencies
    )


def _transport_candidate_8616(
    clinic: object,
    product: EntryJumpTransportProof8616,
    candidate: PendingTerminalJump8616,
    record: ClinicConvertedBlockCapture8616 | None,
    admitted: Mapping[tuple[int, int], AdmittedTerminalJump8616],
    next_atom: Callable[[], int],
) -> ClinicEntryJumpDecision8616:
    """Bind one pending candidate's AIL terminal or return its typed refusal."""
    decoded = candidate.decoded
    if record is None:
        return _decision_8616(
            candidate,
            refusal=ClinicEntryJumpTransportRefusal8616.BLOCK_CENSUS_MISMATCH,
            detail="converted census lacks the pending block",
        )
    admission = admitted.get((candidate.block_addr, decoded.head))
    if admission is None:
        return _decision_8616(
            candidate,
            refusal=ClinicEntryJumpTransportRefusal8616.ADMISSION_MISSING,
            detail=_refusal_for_candidate_8616(product, candidate.block_addr),
        )
    if not _unconditional_8616(admission):
        return _decision_8616(
            candidate,
            refusal=(
                ClinicEntryJumpTransportRefusal8616.ADMISSION_SCOPE_UNSUPPORTED
            ),
            detail=(
                "admission retains an invocation premise, scope, or call "
                "dependencies this transport does not consume"
            ),
        )
    if record.vex is not cast("_BlockBytesBoundary8616", record.block).vex:
        return _decision_8616(
            candidate,
            refusal=ClinicEntryJumpTransportRefusal8616.SOURCE_BYTES_STALE,
            detail="converted block's VEX object changed after capture",
        )
    offset = decoded.head - record.addr
    if (
        offset < 0
        or offset + decoded.encoded_size != len(record.source_bytes)
    ):
        return _decision_8616(
            candidate,
            refusal=(
                ClinicEntryJumpTransportRefusal8616.SOURCE_EXTENT_MISMATCH
            ),
            detail="decoded terminal does not bound the converted block extent",
        )
    if record.source_bytes[offset:] != decoded.encoding:
        return _decision_8616(
            candidate,
            refusal=(
                ClinicEntryJumpTransportRefusal8616.TERMINAL_ENCODING_MISMATCH
            ),
            detail="converted block tail bytes differ from the decoded edge",
        )
    binding = rebind_terminal_jump_8616(
        record.converted,
        record.vex,
        decoded,
        admission.target,
        next_atom=next_atom,
    )
    if not binding.applied:
        return _decision_8616(
            candidate,
            refusal=binding.refusal,
            detail=binding.detail,
        )
    return _decision_8616(candidate, applied=True, target=admission.target)


class _ClinicProjectBlocks8616(Protocol):
    """Third-party Clinic project identity consumed by the native producer."""

    project: object


def _refused_pass_8616(
    captures: Mapping[tuple[int, int], ClinicConvertedBlockCapture8616],
    product: EntryJumpTransportProof8616,
    refusal: ClinicEntryJumpTransportRefusal8616,
    detail: str,
) -> ClinicEntryJumpTransport8616:
    """Refuse every pending candidate under one typed transport reason."""
    pending = product.pending_terminal_jumps()
    decisions = tuple(
        _decision_8616(candidate, refusal=refusal, detail=detail)
        for _addr, candidate in sorted(pending.items())
    )
    return ClinicEntryJumpTransport8616(
        status=(
            ClinicEntryJumpTransportStatus8616.EMPTY
            if not decisions
            else ClinicEntryJumpTransportStatus8616.REFUSED
        ),
        proof=product,
        decisions=decisions,
        stats=ClinicTerminalControlStats8616(
            raw_fact_count=len(captures),
            normalized_fact_count=len(pending),
            classified_fact_count=len(pending),
            materialized_count=0,
            failure_count=len(pending),
        ),
        detail=detail,
    )


def transport_clinic_entry_jumps_8616(
    clinic: object,
    *,
    next_atom: Callable[[], int],
) -> ClinicEntryJumpTransport8616:
    """Consume the bound entry-domain proof once per Clinic conversion.

    Runs one bounded native proof per conversion. Re-conversion gets a
    fresh proof rather than trusting a report over previous AIL objects. The pending set is exactly the domain owner's candidate map over
    the raw import — the same decoded carriers the proof consumed. Every
    candidate either rebinds its terminal ``Jump`` under an unconditional
    admission and the shared binding checks, or keeps its symbolic operand
    under a typed refusal.
    """
    report = _transport_once_8616(clinic, next_atom)
    record_clinic_entry_jump_transport_8616(clinic, report)
    return report


def _transport_once_8616(
    clinic: object, next_atom: Callable[[], int],
) -> ClinicEntryJumpTransport8616:
    """Run the single bounded proof and consume it into captured blocks."""
    captures = _captures_8616(clinic)
    if _pending_transport_reports_8616(clinic) == 0:
        return ClinicEntryJumpTransport8616(
            status=ClinicEntryJumpTransportStatus8616.EMPTY,
            proof=None,
            stats=ClinicTerminalControlStats8616(
                raw_fact_count=len(captures),
                normalized_fact_count=0,
                classified_fact_count=0,
                materialized_count=0,
                failure_count=0,
            ),
            detail="no pending terminal jumps",
        )
    if not _context_is_current_8616(clinic, captures):
        count = _pending_transport_reports_8616(clinic)
        return ClinicEntryJumpTransport8616(
            status=ClinicEntryJumpTransportStatus8616.REFUSED,
            proof=None,
            refusal=ClinicEntryJumpTransportRefusal8616.CONTEXT_STALE,
            detail="conversion context no longer matches native source and graph",
            stats=ClinicTerminalControlStats8616(len(captures), count, count, 0, count),
        )
    from inertia.ir.entry_jump_transport import prove_entry_jump_transport_8616

    product = prove_entry_jump_transport_8616(
        cast("_ClinicProjectBlocks8616", clinic).project,
        cast("_ClinicFunctionBoundary8616", clinic).function,
    )
    if (
        product.project is not cast("_ClinicProjectBlocks8616", clinic).project
        or product.function
        is not cast("_ClinicFunctionBoundary8616", clinic).function
    ):
        return _refused_pass_8616(
            captures,
            product,
            ClinicEntryJumpTransportRefusal8616.FOREIGN_PRODUCT,
            "proof product is not bound to this clinic's project/function",
        )
    if product.refusal is not None:
        return _refused_pass_8616(
            captures,
            product,
            ClinicEntryJumpTransportRefusal8616.PROOF_REFUSED,
            product.refusal.detail,
        )
    if not _context_is_current_8616(clinic, captures):
        return _refused_pass_8616(
            captures, product, ClinicEntryJumpTransportRefusal8616.CONTEXT_STALE,
            "native context changed while the entry-domain proof ran",
        )
    converted_census = sorted(record.addr for record in captures.values())
    imported_census = sorted(
        block.addr for block in product.bundle.artifact.blocks
    )
    if converted_census != imported_census:
        return _refused_pass_8616(
            captures,
            product,
            ClinicEntryJumpTransportRefusal8616.BLOCK_CENSUS_MISMATCH,
            "converted block census differs from the proved surface",
        )
    from inertia.ir.entry_jump_transport import EntryJumpTransportProof8616

    from .clinic_scoped_control import ClinicScopedPartition8616

    # Dynamic third-party boundary: only universal partitions use this proof product.
    partition = getattr(clinic, "_inertia_clinic_scoped_partition_8616", None)
    if (partition is not None and type(partition) is ClinicScopedPartition8616
            and type(partition.entry) is EntryJumpTransportProof8616):
        application = product.application
        expected_edges = (() if application is None else tuple(sorted(
            (block.addr, target) for block in application.blocks for target in block.successor_addrs)))
        if application is None or partition.consuming_graph.edges != expected_edges:
            return _refused_pass_8616(
                captures, product, ClinicEntryJumpTransportRefusal8616.CONTEXT_STALE,
                "universal partition no longer matches freshly proved native successors")
    return _consume_admissions_8616(clinic, captures, product, next_atom)


def _consume_admissions_8616(
    clinic: object,
    captures: Mapping[tuple[int, int], ClinicConvertedBlockCapture8616],
    product: EntryJumpTransportProof8616,
    next_atom: Callable[[], int],
) -> ClinicEntryJumpTransport8616:
    """Close every pending decision after whole-context authentication."""
    pending = product.pending_terminal_jumps()
    admitted = {
        (jump.block_addr, jump.head): jump
        for jump in product.admitted_terminal_jumps()
    }
    captures_by_addr: dict[int, ClinicConvertedBlockCapture8616] = {}
    for record in captures.values():
        if record.addr in captures_by_addr:
            return _refused_pass_8616(
                captures,
                product,
                ClinicEntryJumpTransportRefusal8616.BLOCK_CENSUS_MISMATCH,
                "converted census carries duplicate block addresses",
            )
        captures_by_addr[record.addr] = record
    decisions: list[ClinicEntryJumpDecision8616] = []
    materialized = 0
    for block_addr in sorted(pending):
        candidate = pending[block_addr]
        decision = _transport_candidate_8616(
            clinic,
            product,
            candidate,
            captures_by_addr.get(block_addr),
            admitted,
            next_atom,
        )
        decisions.append(decision)
        materialized += int(decision.applied)
    failures = len(pending) - materialized
    if not pending:
        status = ClinicEntryJumpTransportStatus8616.EMPTY
    elif failures == 0:
        status = ClinicEntryJumpTransportStatus8616.TRANSPORTED
    elif materialized:
        status = ClinicEntryJumpTransportStatus8616.PARTIAL
    else:
        status = ClinicEntryJumpTransportStatus8616.REFUSED
    return ClinicEntryJumpTransport8616(
        status=status,
        proof=product,
        decisions=tuple(decisions),
        stats=ClinicTerminalControlStats8616(
            raw_fact_count=len(captures),
            normalized_fact_count=len(pending),
            classified_fact_count=len(pending),
            materialized_count=materialized,
            failure_count=failures,
        ),
    )


class _ClinicFunctionBoundary8616(Protocol):
    """Third-party Clinic surface naming the recovered function object."""

    function: object


def record_clinic_entry_jump_transport_8616(
    clinic: object, report: ClinicEntryJumpTransport8616,
) -> None:
    """Append one report to the clinic's typed entry-transport ledger.

    Dynamic boundary: the ledger attribute lives on the third-party Clinic
    instance; tuple-append keeps earlier decisions immutable.
    """
    reports = getattr(clinic, CLINIC_ENTRY_JUMP_TRANSPORT_ATTR_8616, ())
    if not isinstance(reports, tuple):
        reports = ()
    setattr(clinic, CLINIC_ENTRY_JUMP_TRANSPORT_ATTR_8616, (*reports, report))
