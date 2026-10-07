"""Reuse native terminal-jump evidence for callee candidate discovery.

Layer: tools/dosunit source-bound callee intake.
Responsibility: recover full loaded near-call and jump targets only when the existing IR
owner proves the exact bytes and VEX expression agree across the architectural
selector domain. CALL uses the same native relative-control evidence owner. This is discovery
evidence, not callee equivalence or return
restoration. Indirect and selector-dependent controls remain unresolved.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, NoReturn, cast

if TYPE_CHECKING:
    from inertia.ir.vex_terminal_jump import TerminalJumpEvidenceStats8616, TerminalJumpRefusalReason8616

import pyvex


@dataclass(frozen=True, slots=True)
class _NativeBlock:
    """Exact source bytes exposed to the native terminal-jump boundary."""

    addr: int
    size: int
    bytes: bytes


def proven_terminal_target(
    irsb: pyvex.IRSB, body: bytes, *, head: int, size: int,
) -> int | None:
    """Consume the native jump theorem without narrowing or assuming CS.

    The scanner has already verified the body against live source bytes.
    Keep the expression symbolic for subsequent lowering and composition;
    only publish the theorem's full-width discovery destination.
    """
    # The IR package must initialize after the frontend bootstrap, as in the
    # existing angr direct-jump resolver that consumes this same theorem.
    from inertia.ir.vex_terminal_jump import terminal_direct_jump_evidence_8616

    evidence = terminal_direct_jump_evidence_8616(
        _NativeBlock(irsb.addr, len(body), body), irsb,
        instruction_addr=head, instruction_size=size,
        tmp_exprs={statement.tmp: statement.data for statement in irsb.statements
                   if isinstance(statement, pyvex.stmt.WrTmp)},
        type_environment=irsb.tyenv,
    )
    if evidence.failure is not None or not evidence.stats.closed:
        return None
    return cast(int | None, evidence.proven_target)


class RelativeCallTargetFailure(StrEnum):
    """Exact boundary preventing publication of a direct relative CALL target."""

    SOURCE_INCOMPLETE = "source_incomplete"
    FORM_UNSUPPORTED = "form_unsupported"
    NATIVE_REFUSED = "native_refused"


@dataclass(frozen=True, slots=True)
class RelativeCallTarget:
    """Typed discovery result; a target is never a callee equivalence claim."""

    target: int | None
    failure: RelativeCallTargetFailure | None
    native_failure: TerminalJumpRefusalReason8616 | None = None
    stats: TerminalJumpEvidenceStats8616 | None = None


def relative_call_target(
    irsb: pyvex.IRSB, *, head: int, encoding: bytes,
) -> RelativeCallTarget:
    """Bind one terminal CALL's exact bytes to the full native control DAG."""
    from inertia.frontend.x86_16.relative_control_edge import DecodedRelativeEdge, decode_relative_edge
    from inertia.ir.vex_terminal_jump import native_relative_call_evidence_8616

    if (irsb.jumpkind != "Ijk_Call" or not encoding or head < irsb.addr
            or head + len(encoding) != irsb.addr + irsb.size):
        return RelativeCallTarget(None, RelativeCallTargetFailure.SOURCE_INCOMPLETE)
    decoded = decode_relative_edge(head, encoding, source="ssa_call_transfer")
    if not isinstance(decoded, DecodedRelativeEdge) or not decoded.is_call:
        return RelativeCallTarget(None, RelativeCallTargetFailure.FORM_UNSUPPORTED)
    evidence = native_relative_call_evidence_8616(
        decoded, irsb.next,
        {statement.tmp: statement.data for statement in irsb.statements
         if isinstance(statement, pyvex.stmt.WrTmp)},
        irsb.tyenv,
    )
    if evidence.failure is not None or not evidence.stats.closed or evidence.proven_target is None:
        return RelativeCallTarget(None, RelativeCallTargetFailure.NATIVE_REFUSED,
                                  evidence.failure, evidence.stats)
    return RelativeCallTarget(evidence.proven_target, None, stats=evidence.stats)



def _concrete_far_coordinate(value: object, width: object) -> NoReturn:
    """Reject a symbolic value at the exact far-immediate byte boundary."""
    raise TypeError(f"far immediate projection requires concrete values: {value!r}:{width!r}")


def far_call_target(irsb: pyvex.IRSB, *, encoding: bytes, offset_bytes: int) -> RelativeCallTarget:
    """Keep a far native constant only when it equals the complete encoded pointer.

    The caller has decoded the exact bytes into a far CALL frame. This
    boundary admits only its immediate 9A form; indirect forms stay unknown.
    """
    from inertia.frontend.x86_16.control_coordinates import ControlWidth, linear_continuation

    opcode_index = len(encoding) - offset_bytes - 3
    if offset_bytes not in (2, 4) or opcode_index < 0 or encoding[opcode_index] != 0x9A:
        return RelativeCallTarget(None, RelativeCallTargetFailure.FORM_UNSUPPORTED)
    offset = int.from_bytes(encoding[opcode_index + 1:-2], "little")
    selector = int.from_bytes(encoding[-2:], "little")
    expected = linear_continuation(selector, offset, ControlWidth(offset_bytes * 8), _concrete_far_coordinate)
    if not isinstance(irsb.next, pyvex.expr.Const) or irsb.next.con.value != expected:
        return RelativeCallTarget(None, RelativeCallTargetFailure.NATIVE_REFUSED)
    return RelativeCallTarget(int(irsb.next.con.value), None)



def native_constant_control(irsb: pyvex.IRSB) -> int | None:
    """Read a literal native destination through bounded tmp and PC-write aliases.

    Flat32 opt-level-zero CALL blocks end in GET(eip) after PUT(eip, target).
    Respect each read's statement position and reject overlapping partial
    writes; instruction text and decoded target guesses play no part.
    """
    expression = irsb.next
    position = len(irsb.statements)
    for _ in range(16):
        if expression.result_size(irsb.tyenv) != 32:
            return None
        if isinstance(expression, pyvex.expr.Const):
            raw = expression.con.value
            if not isinstance(raw, int):
                return None  # F32/F64 immediates are not control targets
            return raw
        if isinstance(expression, pyvex.expr.RdTmp):
            definitions = [(index, statement) for index, statement in enumerate(irsb.statements[:position])
                           if isinstance(statement, pyvex.stmt.WrTmp) and statement.tmp == expression.tmp]
            if len(definitions) != 1:
                return None
            position, definition = definitions[0]
            expression = definition.data
            continue
        if not isinstance(expression, pyvex.expr.Get) or expression.offset != irsb.arch.ip_offset:
            return None
        producer = _native_pc_write(irsb, position, expression.offset)
        if producer is None:
            return None
        position, expression = producer

    return None



def _native_pc_write(
    irsb: pyvex.IRSB, position: int, offset: int,
) -> tuple[int, pyvex.expr.IRExpr] | None:
    """Resolve a PC read to its preceding complete write, refusing partial aliases."""
    for index in range(position - 1, -1, -1):
        statement = irsb.statements[index]
        if isinstance(statement, pyvex.stmt.PutI):
            return None
        if not isinstance(statement, pyvex.stmt.Put):
            continue
        size = statement.data.result_size(irsb.tyenv) // 8
        if statement.offset + size <= offset or statement.offset >= offset + 4:
            continue
        if statement.offset != offset or size != 4:
            return None
        return index, statement.data
    return None
