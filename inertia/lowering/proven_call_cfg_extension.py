"""Bounded candidate-private CFG extension across proven near CALL targets.

Layer: lowering / object recovery.
Responsibility: re-run bounded CFGFast for one recovered caller plus the
callee entry points proven by the frontend's own native near-CALL binding
(``frontend_cfg_direct_call.native_direct_call_evidence_8616``). Only a
``DirectNearCallTargetBinding8616`` whose ``complete`` verdict retains exact
caller/callsite identity may seed a callee; indirect, far, operand-prefixed,
unproven, and evidence-free terminal calls stay typed refusals in the
receipt. The extension is one level, non-recursive, capped at
``max_targets`` unique callees of ``callee_window`` bytes each, and never
widens the caller's own regions to reach a neighbor.

The returned CFG owns an independent ``KnowledgeBase`` so the previously
selected candidate pair survives intact; the caller is re-bound by address
inside the new KB, never copied across KBs, and the project-global KB is
never mutated.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, cast

import angr
import pyvex
from angr import KnowledgeBase

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.control_coordinates import ControlAddressDomain
from inertia.frontend.x86_16.frontend_cfg_direct_call import (
    native_direct_call_evidence_8616,
)
from inertia.frontend.x86_16.relative_control_edge import (
    RelativeEdgeRefusal,
    RelativeEdgeRefusalReason,
)
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallTargetBinding8616,
    DirectNearCallTargetBindingFailure8616,
)

from .analysis_helpers import seed_calling_conventions

__all__ = [
    "PROVEN_CALLEE_MAX_TARGETS_8616",
    "PROVEN_CALLEE_WINDOW_8616",
    "ProvenCallAdmission8616",
    "ProvenCallCfgExtension8616",
    "ProvenCallExtensionLimit8616",
    "ProvenCallExtensionReceipt8616",
    "ProvenCallSiteRecord8616",
    "collect_proven_call_targets_8616",
    "extend_cfg_for_proven_calls_8616",
]

PROVEN_CALLEE_WINDOW_8616: int = 0x200
PROVEN_CALLEE_MAX_TARGETS_8616: int = 32


class ProvenCallAdmission8616(StrEnum):
    """Bounded admission verdict for one collected terminal-CALL surface."""

    PROVEN_ADMITTED = "proven_admitted"
    PROVEN_DUPLICATE = "proven_duplicate"
    PROVEN_SELF_TARGET = "proven_self_target"
    PROVEN_CAP_REFUSED = "proven_cap_refused"
    REFUSED_UNPROVEN = "refused_unproven"
    REFUSED_UNSUPPORTED = "refused_unsupported"
    REFUSED_NO_EVIDENCE = "refused_no_evidence"
    REFUSED_FOREIGN_SITE = "refused_foreign_site"


class ProvenCallExtensionLimit8616(StrEnum):
    """Fixed bound that refused otherwise-admissible proven callees."""

    UNIQUE_TARGET_CAP = "unique_target_cap"


@dataclass(frozen=True, slots=True)
class ProvenCallSiteRecord8616:
    """One collected terminal-CALL surface and its admission outcome.

    ``callsite_addr``/``target_addr`` keep the proven binding's exact
    coordinates; ``failure`` retains the typed refusal owner verdict for
    unadmitted surfaces so nothing proven-but-refused becomes invisible.
    """

    block_addr: int
    callsite_addr: int | None
    target_addr: int | None
    status: ProvenCallAdmission8616
    failure: (
        DirectNearCallTargetBindingFailure8616 | RelativeEdgeRefusalReason | None
    ) = None

    def to_dict(self) -> dict[str, object]:
        """Serialize the record for receipts and diagnostics."""
        return {
            "block_addr": self.block_addr,
            "callsite_addr": self.callsite_addr,
            "target_addr": self.target_addr,
            "status": self.status.value,
            "failure": None if self.failure is None else str(self.failure),
        }


@dataclass(frozen=True, slots=True)
class ProvenCallExtensionReceipt8616:
    """Closed census of every terminal-CALL surface seen in one caller.

    ``records`` counts all collected surfaces exactly once; proven targets
    that are duplicates, self-calls, or over the fixed cap are recorded as
    refusals instead of being silently truncated.
    """

    caller_addr: int
    blocks_scanned: int
    records: tuple[ProvenCallSiteRecord8616, ...]
    max_targets: int

    @property
    def collected_count(self) -> int:
        """Return terminal-CALL surfaces evaluated for evidence."""
        return len(self.records)

    def _count(self, status: ProvenCallAdmission8616) -> int:
        return sum(1 for record in self.records if record.status is status)

    @property
    def proven_count(self) -> int:
        """Return surfaces whose native binding verdict was complete."""
        return (
            self._count(ProvenCallAdmission8616.PROVEN_ADMITTED)
            + self._count(ProvenCallAdmission8616.PROVEN_DUPLICATE)
            + self._count(ProvenCallAdmission8616.PROVEN_SELF_TARGET)
            + self._count(ProvenCallAdmission8616.PROVEN_CAP_REFUSED)
        )

    @property
    def admitted_count(self) -> int:
        """Return proven unique callees admitted as extra CFG starts."""
        return self._count(ProvenCallAdmission8616.PROVEN_ADMITTED)

    @property
    def refused_count(self) -> int:
        """Return collected surfaces that did not seed a callee."""
        return self.collected_count - self.admitted_count

    @property
    def cap_refused_count(self) -> int:
        """Return proven unique callees refused only by the fixed cap."""
        return self._count(ProvenCallAdmission8616.PROVEN_CAP_REFUSED)

    @property
    def limit_reason(self) -> ProvenCallExtensionLimit8616 | None:
        """Return the fixed bound that refused admissible callees, if any."""
        if self.cap_refused_count:
            return ProvenCallExtensionLimit8616.UNIQUE_TARGET_CAP
        return None

    def admitted_targets(self) -> tuple[int, ...]:
        """Return the admitted unique callee entry addresses, in order."""
        return tuple(
            cast(int, record.target_addr)
            for record in self.records
            if record.status is ProvenCallAdmission8616.PROVEN_ADMITTED
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize the closed census for diagnostics and workers."""
        return {
            "caller_addr": self.caller_addr,
            "blocks_scanned": self.blocks_scanned,
            "collected_count": self.collected_count,
            "proven_count": self.proven_count,
            "admitted_count": self.admitted_count,
            "refused_count": self.refused_count,
            "cap_refused_count": self.cap_refused_count,
            "limit_reason": (
                None if self.limit_reason is None else self.limit_reason.value
            ),
            "records": [record.to_dict() for record in self.records],
        }


@dataclass(frozen=True, slots=True)
class ProvenCallCfgExtension8616:
    """Extended candidate-private CFG plus the caller rebound inside it.

    ``cfg``/``function`` are ``None`` when no proven callee was admitted;
    the receipt remains so refused surfaces stay observable.
    ``body_targets`` are the admitted targets whose extended-CFG function
    actually holds recovered blocks — a seeded target without body (for
    example a ``create=True`` manager shell) is never claimed complete.
    """

    cfg: object | None
    function: object | None
    receipt: ProvenCallExtensionReceipt8616
    body_targets: tuple[int, ...] = ()


type EvidenceProvider8616 = Callable[..., object]


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> object:
    """Read a dynamic third-party (angr) attribute at the plugin boundary."""
    return getattr(obj, name, default)


def _validate_max_targets_8616(max_targets: int) -> int:
    """Enforce the fixed unique-callee ceiling before any evidence work."""
    if type(max_targets) is not int or not 0 <= max_targets <= PROVEN_CALLEE_MAX_TARGETS_8616:
        raise ValueError(
            f"max_targets must be an int in 0..{PROVEN_CALLEE_MAX_TARGETS_8616}, "
            f"got {max_targets!r}"
        )
    return max_targets


def _validate_callee_window_8616(callee_window: int) -> int:
    """Enforce the fixed per-callee byte window before any evidence work."""
    if type(callee_window) is not int or not 1 <= callee_window <= PROVEN_CALLEE_WINDOW_8616:
        raise ValueError(
            f"callee_window must be an int in 1..{PROVEN_CALLEE_WINDOW_8616}, "
            f"got {callee_window!r}"
        )
    return callee_window


def _terminal_call_facts_8616(vex: object) -> tuple[int, int] | None:
    """Return the terminal CALL instruction's ``(head, end)`` from IMarks."""
    if not isinstance(vex, pyvex.IRSB):
        return None
    marks = [
        row
        for row in vex.statements
        if isinstance(row, pyvex.stmt.IMark)
    ]
    if not marks:
        return None
    last = marks[-1]
    head = int(cast(Any, last.addr)) + int(cast(Any, last.delta))
    return head, head + int(cast(Any, last.len))


def _caller_block_bounds_8616(function: object) -> tuple[tuple[int, int], ...]:
    """Return sorted unique ``(addr, size)`` bounds of the caller's blocks."""
    bounds: set[tuple[int, int]] = set()
    blocks = cast(Any, _dynamic_attr_8616(function, "blocks", ()))
    for block in tuple(blocks or ()):
        addr = _dynamic_attr_8616(block, "addr", None)
        size = _dynamic_attr_8616(block, "size", None)
        if isinstance(addr, int) and isinstance(size, int) and size > 0:
            bounds.add((addr, size))
    return tuple(sorted(bounds))


def _caller_covered_regions_8616(function: object) -> tuple[tuple[int, int], ...]:
    """Return merged disjoint regions covering exactly the caller's blocks.

    These bounds describe only what recovery already proved; they never
    widen to reach callee neighbors.
    """
    spans = sorted(
        (addr, addr + size) for addr, size in _caller_block_bounds_8616(function)
    )
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return tuple(merged)


def _binding_binds_this_surface_8616(
    evidence: DirectNearCallTargetBinding8616,
    block_addr: int,
    block_end: int,
    terminal_head: int,
    terminal_end: int,
) -> bool:
    """Bind a complete verdict to *this* retained block's terminal call.

    A complete binding is still foreign evidence unless its callsite is the
    retained last-IMark call head inside this block and its proven
    continuation ``shape.next_linear_addr`` is the exact terminal
    instruction end, which is also the native block end. An injected or
    unrelated complete verdict cannot bypass this consumer identity check.
    """
    return bool(
        evidence.callsite_addr == terminal_head
        and block_addr <= terminal_head < block_end
        and terminal_end == block_end
        and evidence.shape is not None
        and evidence.shape.next_linear_addr == terminal_end
    )


def _classify_call_surface_8616(
    project: object,
    block_addr: int,
    block_size: int,
    discovery_irsb: object,
    terminal_head: int,
    terminal_end: int,
    provider: EvidenceProvider8616,
) -> ProvenCallSiteRecord8616:
    """Evaluate one terminal-CALL block into a typed admission verdict."""
    evidence = provider(
        project,
        block_addr=block_addr,
        block_size=block_size,
        discovery_irsb=discovery_irsb,
    )
    if isinstance(evidence, DirectNearCallTargetBinding8616):
        block_end = block_addr + block_size
        if (
            evidence.complete
            and isinstance(evidence.callsite_addr, int)
            and isinstance(evidence.target_addr, int)
        ):
            status = (
                ProvenCallAdmission8616.PROVEN_ADMITTED
                if _binding_binds_this_surface_8616(
                    evidence, block_addr, block_end, terminal_head, terminal_end
                )
                else ProvenCallAdmission8616.REFUSED_FOREIGN_SITE
            )
            failure: (
                DirectNearCallTargetBindingFailure8616 | RelativeEdgeRefusalReason | None
            ) = None
        else:
            status = ProvenCallAdmission8616.REFUSED_UNPROVEN
            failure = evidence.failure
        return ProvenCallSiteRecord8616(
            block_addr=block_addr,
            callsite_addr=evidence.callsite_addr,
            target_addr=evidence.target_addr,
            status=status,
            failure=failure,
        )
    if isinstance(evidence, RelativeEdgeRefusal):
        return ProvenCallSiteRecord8616(
            block_addr=block_addr,
            callsite_addr=evidence.head,
            target_addr=None,
            status=ProvenCallAdmission8616.REFUSED_UNSUPPORTED,
            failure=evidence.reason,
        )
    if evidence is None:
        return ProvenCallSiteRecord8616(
            block_addr=block_addr,
            callsite_addr=None,
            target_addr=None,
            status=ProvenCallAdmission8616.REFUSED_NO_EVIDENCE,
        )
    raise TypeError(
        "native direct-call evidence provider returned an unsupported "
        f"verdict type {type(evidence).__name__} for block {block_addr:#x}"
    )


def _admission_status_for_target_8616(
    target: int, caller_addr: int, admitted: set[int], max_targets: int
) -> ProvenCallAdmission8616:
    """Apply self/duplicate/cap accounting to a proven admitted target."""
    if target == caller_addr:
        return ProvenCallAdmission8616.PROVEN_SELF_TARGET
    if target in admitted:
        return ProvenCallAdmission8616.PROVEN_DUPLICATE
    if len(admitted) >= max_targets:
        return ProvenCallAdmission8616.PROVEN_CAP_REFUSED
    admitted.add(target)
    return ProvenCallAdmission8616.PROVEN_ADMITTED


def _census_call_surface_8616(
    project: object,
    caller_addr: int,
    block_addr: int,
    block_size: int,
    vex: pyvex.IRSB,
    provider: EvidenceProvider8616,
    admitted: set[int],
    max_targets: int,
) -> ProvenCallSiteRecord8616:
    """Classify one terminal-CALL block and apply admission accounting."""
    terminal = _terminal_call_facts_8616(vex)
    if terminal is None:
        return ProvenCallSiteRecord8616(
            block_addr=block_addr,
            callsite_addr=None,
            target_addr=None,
            status=ProvenCallAdmission8616.REFUSED_NO_EVIDENCE,
        )
    record = _classify_call_surface_8616(
        project, block_addr, block_size, vex, terminal[0], terminal[1], provider
    )
    if record.status is not ProvenCallAdmission8616.PROVEN_ADMITTED:
        return record
    status = _admission_status_for_target_8616(
        cast(int, record.target_addr), caller_addr, admitted, max_targets
    )
    if status is ProvenCallAdmission8616.PROVEN_ADMITTED:
        return record
    return ProvenCallSiteRecord8616(
        block_addr=record.block_addr,
        callsite_addr=record.callsite_addr,
        target_addr=record.target_addr,
        status=status,
        failure=record.failure,
    )


def collect_proven_call_targets_8616(
    project: object,
    function: object,
    *,
    max_targets: int = PROVEN_CALLEE_MAX_TARGETS_8616,
    evidence_provider: EvidenceProvider8616 | None = None,
) -> ProvenCallExtensionReceipt8616 | None:
    """Evaluate every retained caller block's terminal near CALL exactly.

    Each block is re-lifted at ``opt_level=0`` so the supplied discovery
    operand is the same instruction stream the native re-lift proves; only
    ``binding.complete`` verdicts with exact caller/callsite identity seed
    callees. Proven targets are deduplicated by address, self-calls and
    over-cap targets stay observable as typed refusals, and admission order
    is callsite order for determinism.

    Returns ``None`` for non-x86-16 projects and callers without a concrete
    entry address; there is no evaluable native surface to census.
    """
    _validate_max_targets_8616(max_targets)
    if not (
        isinstance(project, angr.Project)
        and isinstance(project.arch, Arch86_16)
        and project.arch.control_address_domain is ControlAddressDomain.LOADER_LINEAR
    ):
        return None
    caller_addr = _dynamic_attr_8616(function, "addr", None)
    if not isinstance(caller_addr, int):
        return None
    provider = evidence_provider or native_direct_call_evidence_8616

    records: list[ProvenCallSiteRecord8616] = []
    admitted: set[int] = set()
    for block_addr, block_size in _caller_block_bounds_8616(function):
        native = project.factory.block(block_addr, size=block_size, opt_level=0)
        vex = native.vex
        if not isinstance(vex, pyvex.IRSB) or str(vex.jumpkind) != "Ijk_Call":
            continue
        records.append(
            _census_call_surface_8616(
                project, caller_addr, block_addr, block_size, vex, provider,
                admitted, max_targets,
            )
        )
    return ProvenCallExtensionReceipt8616(
        caller_addr=caller_addr,
        blocks_scanned=len(_caller_block_bounds_8616(function)),
        records=tuple(records),
        max_targets=max_targets,
    )


def extend_cfg_for_proven_calls_8616(
    project: object,
    cfg: object,
    function: object,
    *,
    caller_regions: Sequence[tuple[int, int]] | None = None,
    callee_window: int = PROVEN_CALLEE_WINDOW_8616,
    max_targets: int = PROVEN_CALLEE_MAX_TARGETS_8616,
    seed_calling_conventions_enabled: bool = True,
    evidence_provider: EvidenceProvider8616 | None = None,
) -> ProvenCallCfgExtension8616 | None:
    """Re-run bounded CFGFast with only proven near-CALL callees seeded.

    The caller keeps exactly its recovered regions — ``caller_regions`` when
    supplied, otherwise the merged coverage of its own blocks — while each
    admitted callee gets an independent ``callee_window`` region. One level,
    no recursion: callees' own calls are not re-extended here.

    The returned extension's CFG owns an independent ``KnowledgeBase``; the
    caller is re-bound by address inside it, the supplied ``cfg`` is only
    context and is never mutated, and the project KB is untouched.
    ``None`` means there was no evaluable native caller surface
    (non-x86-16 or missing entry); a result with ``cfg=None`` means surfaces
    were evaluated but nothing was admitted — the receipt records why.
    """
    del cfg  # context only; extension never mutates the supplied CFG or KB
    _validate_max_targets_8616(max_targets)
    _validate_callee_window_8616(callee_window)
    receipt = collect_proven_call_targets_8616(
        project,
        function,
        max_targets=max_targets,
        evidence_provider=evidence_provider,
    )
    if receipt is None:
        return None
    targets = receipt.admitted_targets()
    if not targets:
        return ProvenCallCfgExtension8616(None, None, receipt)

    regions = list(caller_regions) if caller_regions is not None else list(
        _caller_covered_regions_8616(function)
    )
    if not regions:
        logging.getLogger(__name__).debug(
            "x86-16 proven-call extension refused: caller %s has no recovered bounds",
            hex(receipt.caller_addr),
        )
        return ProvenCallCfgExtension8616(None, None, receipt)
    regions.extend((target, target + callee_window) for target in targets)

    extended = cast(Any, project).analyses.CFGFast(
        kb=KnowledgeBase(cast(Any, project)),
        start_at_entry=False,
        function_starts=sorted({receipt.caller_addr, *targets}),
        # These roots have native call evidence. A prologue-shaped byte string
        # elsewhere in a callee window is not evidence for another root.
        function_prologues=False,
        regions=regions,
        normalize=True,
        force_complete_scan=False,
        force_smart_scan=False,
        resolve_indirect_jumps=False,
    )
    if receipt.caller_addr not in extended.functions:
        logging.getLogger(__name__).debug(
            "x86-16 proven-call extension refused: caller %s absent from extended CFG",
            hex(receipt.caller_addr),
        )
        return ProvenCallCfgExtension8616(None, None, receipt)
    caller = extended.functions[receipt.caller_addr]
    body_targets = tuple(
        target
        for target in targets
        if target in extended.functions
        and bool(_caller_block_bounds_8616(extended.functions[target]))
    )
    for target in targets:
        callee = extended.kb.functions.function(addr=target, create=True)
        if callee is not None:
            callee._init_prototype_and_calling_convention()
    if seed_calling_conventions_enabled:
        seed_calling_conventions(extended)
    return ProvenCallCfgExtension8616(extended, caller, receipt, body_targets)
