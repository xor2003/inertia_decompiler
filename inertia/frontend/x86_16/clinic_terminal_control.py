"""Transport proven native terminal JMP targets into converted AIL blocks.

Layer: Frontend/runtime.
Responsibility: at the Clinic VEX-to-AIL conversion boundary, bind the
per-block terminal direct-jump destination already proven by
``terminal_direct_jump_evidence_8616`` onto the exact ``Jump`` statement that
carries this block's own ``next`` operand, replacing only that operand with
the proven loader-linear ``Expr.Const``. Execution VEX is never mutated;
absent proof, byte/shape/segment mismatches, selector-window refusals,
non-native callers, and non-matching AIL terminals keep the symbolic operand
and are recorded as typed non-results under closed counters. No alias, type,
structuring, or rewrite-stage semantics are recovered here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

import pyvex
from angr import ailment

from inertia.ir.core import IRRefusal
from inertia.ir.vex_terminal_jump import (
    TerminalJumpEvidence8616,
    terminal_direct_jump_evidence_8616,
)

from .control_coordinates import ControlWidth

__all__ = (
    "CLINIC_TERMINAL_TRANSPORT_ATTR_8616",
    "ClinicTerminalControlRefusal8616",
    "ClinicTerminalControlStats8616",
    "ClinicTerminalTransport8616",
    "record_clinic_terminal_transport_8616",
    "transport_terminal_direct_jump_8616",
)

# Typed report ledger stashed on the third-party Clinic instance so the
# per-block transport census survives for diagnostics without owning angr
# state. Tuple-append keeps earlier decisions immutable.
CLINIC_TERMINAL_TRANSPORT_ATTR_8616: str = "_inertia_terminal_jump_transports_8616"


class ClinicTerminalControlRefusal8616(StrEnum):
    """Typed transport reason a classified terminal kept its symbolic operand."""

    TERMINAL_STATEMENT_NOT_JUMP = "clinic_terminal_statement_not_jump"
    NEXT_OPERAND_UNBOUND = "clinic_terminal_next_operand_unbound"
    AIL_TARGET_MISMATCH = "clinic_terminal_ail_target_mismatch"
    AIL_SOURCE_MISMATCH = "clinic_terminal_ail_source_mismatch"
    MISSING_DECODED_EDGE = "clinic_terminal_missing_decoded_edge"
    DECODED_TARGET_MISMATCH = "clinic_terminal_decoded_target_mismatch"
    UNPROVEN_TARGET = "clinic_terminal_unproven_target"


@dataclass(frozen=True, slots=True)
class ClinicTerminalControlStats8616:
    """Closed five-stage ledger for one converted block terminal.

    ``raw_fact_count`` counts the examined ``Ijk_Boring`` terminal;
    ``normalized_fact_count`` and ``classified_fact_count`` are carried from
    the proof owner's own byte-decode and jump-form classification.
    ``materialized_count`` counts AIL terminal operands bound to the proven
    loader-linear constant; ``failure_count`` counts typed refusals from the
    proof owner or this transport, so a classified-but-unbound candidate is a
    counted failure, never a silent drop.
    """

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Every classified candidate either materialized or was refused."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if not all(type(count) is int and count >= 0 for count in counts):
            return False
        return bool(
            self.normalized_fact_count <= self.raw_fact_count
            and self.classified_fact_count <= self.normalized_fact_count
            and self.classified_fact_count
            == self.materialized_count + self.failure_count
        )

    def to_dict(self) -> dict[str, int]:
        """Serialize the transport ledger for diagnostics and workers."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class ClinicTerminalTransport8616:
    """Closed transport decision for one converted AIL block.

    ``applied`` is True only when the exact terminal ``Jump`` carrying this
    block's converted ``next`` operand was re-pointed at ``proven_target``.
    ``evidence`` retains the proof owner's full decision; ``refusal`` is this
    transport's own typed reason when a classified candidate could not be
    bound. Whenever ``applied`` is False the symbolic operand is preserved.
    """

    applied: bool
    proven_target: int | None
    refusal: ClinicTerminalControlRefusal8616 | None
    detail: str
    stats: ClinicTerminalControlStats8616
    evidence: TerminalJumpEvidence8616 | None

    @property
    def refusals(self) -> tuple[IRRefusal, ...]:
        """Return the proof owner's refusals for this block, if evidence ran."""
        return () if self.evidence is None else self.evidence.refusals

    def to_dict(self) -> dict[str, object]:
        """Serialize the decision for diagnostics and workers."""
        return {
            "applied": self.applied,
            "proven_target": self.proven_target,
            "refusal": None if self.refusal is None else self.refusal.value,
            "detail": self.detail,
            "stats": self.stats.to_dict(),
            "evidence": None if self.evidence is None else self.evidence.to_dict(),
        }


class _AngrBlockBoundary8616(Protocol):
    """Third-party angr block surface required by the transport."""

    vex: object


class _VexExitBoundary8616(Protocol):
    """Third-party IRSB surface required before the proof owner is invoked."""

    addr: int
    jumpkind: object
    next: object
    statements: object
    tyenv: object


def _block_vex_8616(block: object) -> object | None:
    """Return the converted block's own VEX, or None when absent."""
    try:
        return cast(_AngrBlockBoundary8616, block).vex
    except AttributeError:
        return None


def _is_boring_8616(vex: object) -> bool:
    """Restrict transport to unconditional-exit block tails."""
    try:
        jumpkind = cast(_VexExitBoundary8616, vex).jumpkind
    except AttributeError:
        return False
    return str(jumpkind) == "Ijk_Boring"


def _vex_statements_8616(vex: object) -> tuple[object, ...]:
    """Return the IRSB statement list, or empty when the surface is absent."""
    try:
        statements = cast(_VexExitBoundary8616, vex).statements
    except AttributeError:
        return ()
    try:
        return tuple(cast("Iterable[object]", statements))
    except TypeError:
        return ()


def _terminal_instruction_mark_8616(vex: object) -> tuple[int, int] | None:
    """Return ``(addr, size)`` of the last decoded instruction, if recorded."""
    marks = [
        row for row in _vex_statements_8616(vex) if isinstance(row, pyvex.stmt.IMark)
    ]
    if not marks:
        return None
    last = marks[-1]
    try:
        return int(last.addr) + int(last.delta), int(last.len)
    except (AttributeError, TypeError, ValueError):
        return None


def _tmp_exprs_8616(vex: object) -> dict[int, object]:
    """Collect ``WrTmp`` producers exactly as the IR and CFG consumers do."""
    return {
        row.tmp: row.data
        for row in _vex_statements_8616(vex)
        if isinstance(row, pyvex.stmt.WrTmp)
    }


def _type_environment_8616(vex: object) -> object | None:
    """Return the IRSB type environment for segment-leaf sizing."""
    try:
        return cast(_VexExitBoundary8616, vex).tyenv
    except AttributeError:
        return None


def _skipped_8616() -> ClinicTerminalTransport8616:
    """Return the closed non-candidate decision: nothing was examined."""
    return ClinicTerminalTransport8616(
        applied=False,
        proven_target=None,
        refusal=None,
        detail="",
        stats=ClinicTerminalControlStats8616(0, 0, 0, 0, 0),
        evidence=None,
    )


def _result_8616(
    *,
    applied: bool,
    proven_target: int | None,
    evidence: TerminalJumpEvidence8616,
    refusal: ClinicTerminalControlRefusal8616 | None,
    detail: str,
) -> ClinicTerminalTransport8616:
    """Close one evaluated decision with transport-adjusted counters."""
    stats = evidence.stats
    return ClinicTerminalTransport8616(
        applied=applied,
        proven_target=proven_target,
        refusal=refusal,
        detail=detail,
        stats=ClinicTerminalControlStats8616(
            raw_fact_count=stats.raw_fact_count,
            normalized_fact_count=stats.normalized_fact_count,
            classified_fact_count=stats.classified_fact_count,
            materialized_count=int(applied),
            failure_count=stats.failure_count + int(refusal is not None),
        ),
        evidence=evidence,
    )


def _bound_next_operand_8616(
    jump: ailment.Stmt.Jump, next_expr: object, type_environment: object,
) -> bool | None:
    """Check the AIL terminal operand is exactly this block's converted ``next``.

    ``True`` binds the ``Jump`` to the same temporary index or constant value
    the IRSB ``next`` carried; ``False`` means a different operand occupies
    the terminal; ``None`` means the ``next`` expression kind carries no
    bindable identity here.
    """
    target = jump.target
    if isinstance(next_expr, pyvex.expr.RdTmp):
        if target.bits != next_expr.result_size(cast(pyvex.IRTypeEnv, type_environment)):
            return False
        return (
            isinstance(target, ailment.Expr.Tmp)
            and target.tmp_idx == next_expr.tmp
        )
    if isinstance(next_expr, pyvex.expr.Const):
        if target.bits != next_expr.result_size(cast(pyvex.IRTypeEnv, type_environment)):
            return False
        return (
            isinstance(target, ailment.Expr.Const)
            and target.value == next_expr.con.value
        )
    return None


def _decoded_target_8616(evidence: TerminalJumpEvidence8616) -> int | None:
    """Recompute the proven destination from the retained exact bytes."""
    decoded = evidence.decoded
    if decoded is None:
        return None
    target: int = decoded.next_head + decoded.displacement
    if decoded.width is ControlWidth.DWORD:
        target &= 0xFFFFFFFF
    return target


def transport_terminal_direct_jump_8616(
    block: object,
    converted: object,
    *,
    next_atom: Callable[[], int],
) -> ClinicTerminalTransport8616:
    """Bind the converted block's proven terminal JMP target, or refuse.

    ``block`` is the angr block boundary whose ``vex`` produced ``converted``;
    it is read, never mutated. ``converted`` is rewritten only at the exact
    terminal ``Jump`` whose operand is this block's own ``next`` expression,
    and only when the shared proof owner already published a loader-linear
    destination for the block's own terminal bytes. Every other outcome keeps
    the operand symbolic and records a typed non-result under closed counters.
    """
    if not isinstance(converted, ailment.Block):
        return _skipped_8616()
    vex = _block_vex_8616(block)
    if vex is None or not _is_boring_8616(vex):
        return _skipped_8616()
    mark = _terminal_instruction_mark_8616(vex)
    if mark is None:
        return _skipped_8616()
    instruction_addr, instruction_size = mark
    evidence = terminal_direct_jump_evidence_8616(
        block,
        vex,
        instruction_addr=instruction_addr,
        instruction_size=instruction_size,
        tmp_exprs=_tmp_exprs_8616(vex),
        type_environment=_type_environment_8616(vex),
    )
    if not evidence.retain:
        return _result_8616(
            applied=False, proven_target=None, evidence=evidence,
            refusal=None, detail="",
        )
    if evidence.proven_target is None:
        refusal = (
            None
            if evidence.failure is not None
            else ClinicTerminalControlRefusal8616.UNPROVEN_TARGET
        )
        detail = (
            evidence.refusals[0].detail
            if evidence.refusals
            else "terminal jump destination was not proven"
        )
        return _result_8616(
            applied=False, proven_target=None, evidence=evidence,
            refusal=refusal, detail=detail,
        )
    return _bind_proven_terminal_8616(converted, vex, evidence, next_atom)


def _bind_proven_terminal_8616(
    converted: ailment.Block,
    vex: object,
    evidence: TerminalJumpEvidence8616,
    next_atom: Callable[[], int],
) -> ClinicTerminalTransport8616:
    """Repoint the exact ``next``-carrying terminal Jump at the proven target.

    Every check here is a binding obligation, not a proof obligation: the
    proof owner already published ``proven_target`` for the block's own
    bytes. A terminal that is not this block's ``next`` operand, or a
    destination that does not recompute from the retained decoded edge,
    keeps the symbolic operand under a typed refusal.
    """
    statements = list(converted.statements)
    terminal = statements[-1] if statements else None
    if not isinstance(terminal, ailment.Stmt.Jump):
        return _result_8616(
            applied=False, proven_target=None, evidence=evidence,
            refusal=ClinicTerminalControlRefusal8616.TERMINAL_STATEMENT_NOT_JUMP,
            detail="converted terminal statement is not a Jump",
        )
    jump = cast(ailment.Stmt.Jump, terminal)
    bound = _bound_next_operand_8616(
        jump, cast(_VexExitBoundary8616, vex).next,
        cast(_VexExitBoundary8616, vex).tyenv,
    )
    if bound is None:
        return _result_8616(
            applied=False, proven_target=None, evidence=evidence,
            refusal=ClinicTerminalControlRefusal8616.NEXT_OPERAND_UNBOUND,
            detail="next operand kind carries no bindable AIL identity",
        )
    if not bound:
        return _result_8616(
            applied=False, proven_target=None, evidence=evidence,
            refusal=ClinicTerminalControlRefusal8616.AIL_TARGET_MISMATCH,
            detail="AIL terminal operand is not this block's next expression",
        )
    mark = _terminal_instruction_mark_8616(vex)
    if (
        converted.addr != cast(_VexExitBoundary8616, vex).addr
        or mark is None
        or jump.tags.get("ins_addr") != mark[0]
    ):
        return _result_8616(
            applied=False, proven_target=None, evidence=evidence,
            refusal=ClinicTerminalControlRefusal8616.AIL_SOURCE_MISMATCH,
            detail="AIL block or terminal instruction differs from source VEX",
        )
    decoded_target = _decoded_target_8616(evidence)
    if decoded_target is None:
        return _result_8616(
            applied=False, proven_target=None, evidence=evidence,
            refusal=ClinicTerminalControlRefusal8616.MISSING_DECODED_EDGE,
            detail="proven target lacks the retained decoded edge",
        )
    if evidence.proven_target != decoded_target:
        return _result_8616(
            applied=False, proven_target=None, evidence=evidence,
            refusal=ClinicTerminalControlRefusal8616.DECODED_TARGET_MISMATCH,
            detail=(
                f"proven target 0x{evidence.proven_target:x} disagrees with "
                f"the decoded edge destination 0x{decoded_target:x}"
            ),
        )
    bits = cast(int, jump.target.bits)
    statements[-1] = ailment.Stmt.Jump(
        jump.idx,
        ailment.Expr.Const(next_atom(), evidence.proven_target, bits),
        target_idx=cast(int | None, jump.target_idx),
        **dict(jump.tags),
    )
    converted.statements = statements
    return _result_8616(
        applied=True, proven_target=evidence.proven_target, evidence=evidence,
        refusal=None, detail="",
    )


def record_clinic_terminal_transport_8616(
    clinic: object, report: ClinicTerminalTransport8616,
) -> None:
    """Append one decision to the clinic's typed transport ledger.

    Dynamic boundary: the ledger attribute lives on the third-party Clinic
    instance; tuple-append keeps earlier per-block decisions immutable.
    """
    reports = getattr(clinic, CLINIC_TERMINAL_TRANSPORT_ATTR_8616, ())
    if not isinstance(reports, tuple):
        reports = ()
    setattr(clinic, CLINIC_TERMINAL_TRANSPORT_ATTR_8616, (*reports, report))
