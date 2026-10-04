"""Retain proven native terminal direct jumps for boring VEX block exits.

Layer: IR.
Responsibility: decide, from the exact decoded bytes of the last machine
instruction and the block's VEX ``next`` operand, whether an ``Ijk_Boring``
block tail is a real unconditional near-relative jump whose instruction and
destination must survive as explicit IR. A loader-linear constant destination
is published only when the ``control_coordinates`` CS-relative composition is
invariant across every segment selector capable of fetching the instruction
under the native architectural fetch domain; otherwise the retained jump
keeps its symbolic operand and the block records a typed refusal.
Conditional, call, far, indirect, and fallthrough block tails never become
jumps here. Do not perform alias, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, cast

from ..relative_control_edge import (
    DecodedRelativeEdge,
    RelativeEdgeForm,
    decode_relative_edge,
)
from .core import IRRefusal
from .regs import register_name_from_offset
from .vex_types import vex_expr_size_bytes

__all__ = (
    "TerminalJumpEvidence8616",
    "TerminalJumpEvidenceStats8616",
    "TerminalJumpRefusalReason8616",
    "terminal_direct_jump_evidence_8616",
)

# Unconditional near-relative forms are the only boring terminals that are
# real transfers. Conditional relatives keep their live untaken edge and are
# never rewritten into an unconditional JMP.
_UNCONDITIONAL_JUMP_FORMS_8616: frozenset[RelativeEdgeForm] = frozenset(
    {
        RelativeEdgeForm.JMP_REL8,
        RelativeEdgeForm.JMP_REL16,
        RelativeEdgeForm.JMP_REL32,
    }
)
_WORD_JUMP_FORMS_8616: frozenset[RelativeEdgeForm] = frozenset(
    {RelativeEdgeForm.JMP_REL8, RelativeEdgeForm.JMP_REL16}
)
_MAX_NEXT_ALIAS_DEPTH_8616 = 16
_CS_SEGMENT_REGISTER_8616 = "cs"
_WORD_OPERAND_BITS_8616 = 16
_DWORD_OPERAND_BITS_8616 = 32


class TerminalJumpRefusalReason8616(StrEnum):
    """Typed reason a retained terminal jump keeps a symbolic destination."""

    NEXT_OPERAND_MALFORMED = "terminal_jump_next_operand_malformed"
    SHAPE_MISMATCH = "terminal_jump_shape_mismatch"
    SEGMENT_DOMAIN_MISMATCH = "terminal_jump_segment_domain_mismatch"
    CONTINUATION_MISMATCH = "terminal_jump_continuation_mismatch"
    DISPLACEMENT_MISMATCH = "terminal_jump_displacement_mismatch"
    SELECTOR_WINDOW_UNPROVED = "terminal_jump_selector_window_unproved"
    CONSTANT_CONFLICT = "terminal_jump_constant_conflict"


@dataclass(frozen=True, slots=True)
class TerminalJumpEvidenceStats8616:
    """Closed five-stage accounting for one evaluated block terminal.

    ``raw_fact_count`` counts the examined terminal; ``normalized_fact_count``
    requires exact instruction bytes decoded into an edge; the remaining
    counts record classification, materialization, and refusal so a
    classified-but-unmaterialized candidate is a counted failure, never a
    silent drop.
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
            self.raw_fact_count == 1
            and self.normalized_fact_count == 1
            and self.classified_fact_count
            == self.materialized_count + self.failure_count
        )

    def to_dict(self) -> dict[str, int]:
        """Serialize the evidence ledger for diagnostics and workers."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class _NextShape8616:
    """Facts recovered from a matched ``next`` operand composition.

    ``next_linear_addr`` is the loader-linear continuation embedded by the
    lifter; ``displacement`` is the masked operand of the architectural add.
    ``segment_register`` and ``second_segment_register`` are the register
    leaves of the two CS composition sites in the word near form, or
    ``None`` for the flat dword composition used by rel32 encodings.
    """

    next_linear_addr: int
    displacement: int
    segment_register: str | None
    second_segment_register: str | None
    control_bits: int


@dataclass(frozen=True, slots=True)
class TerminalJumpEvidence8616:
    """Closed evidence decision for one ``Ijk_Boring`` block terminal.

    ``retain`` is True only when the exact terminal instruction bytes decode
    to an unconditional near-relative jump. ``proven_target`` is a
    loader-linear destination only when the VEX ``next`` operand is the
    lifter's composition for those bytes and the decoded target is reachable
    under every selector in the instruction's fetch domain. ``failure``
    carries the typed reason when the destination could not be proven; the
    same reason is recorded in ``refusals`` for block-level reporting.
    ``decoded`` retains the exact-bytes decoded transfer behind a retained
    jump so a separately proved control-domain theorem can discharge the
    selector-window obligation later without re-reading raw bytes.
    """

    retain: bool
    proven_target: int | None
    refusals: tuple[IRRefusal, ...]
    failure: TerminalJumpRefusalReason8616 | None
    stats: TerminalJumpEvidenceStats8616
    decoded: DecodedRelativeEdge | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize the decision for diagnostics and workers."""
        return {
            "retain": self.retain,
            "proven_target": self.proven_target,
            "failure": None if self.failure is None else self.failure.value,
            "refusals": tuple(refusal.to_dict() for refusal in self.refusals),
            "stats": self.stats.to_dict(),
            "decoded": (
                None
                if self.decoded is None
                else {
                    "head": self.decoded.head,
                    "form": self.decoded.form.value,
                    "next_head": self.decoded.next_head,
                    "displacement": self.decoded.displacement,
                }
            ),
        }


class _VexConstBoundary8616(Protocol):
    """Minimal pyvex constant surface consumed by next-operand matching."""

    value: object


class _VexExprBoundary8616(Protocol):
    """Minimal pyvex expression surface consumed by next-operand matching."""

    tag: object
    tmp: object
    offset: object
    op: object
    args: object
    con: object


class _VexBlockBoundary8616(Protocol):
    """Minimal pyvex block surface: jumpkind plus the next expression."""

    jumpkind: object
    next: object


class _NativeBlockBoundary8616(Protocol):
    """Minimal angr block surface exposing exact lifted bytes."""

    addr: object
    size: object
    bytes: object


def _external_int_8616(value: object) -> int:
    """Coerce external pyvex/angr integer-like values without owning them."""
    return int(cast(Any, value))


def _expr_tag_8616(expr: object | None) -> str:
    """Return a VEX expression tag from the pyvex boundary."""
    if expr is None:
        return ""
    try:
        return str(cast(_VexExprBoundary8616, expr).tag)
    except AttributeError:
        return ""


def _expr_args_8616(expr: object | None) -> tuple[object, ...]:
    """Return VEX expression args from the pyvex boundary."""
    if expr is None:
        return ()
    try:
        args = cast(_VexExprBoundary8616, expr).args
    except AttributeError:
        return ()
    if args is None:
        return ()
    return tuple(cast(Any, args))


def _expr_op_8616(expr: object | None) -> str:
    """Return a VEX expression op token from the pyvex boundary."""
    if expr is None:
        return ""
    try:
        return str(cast(_VexExprBoundary8616, expr).op)
    except AttributeError:
        return ""


def _expr_offset_8616(expr: object) -> int | None:
    """Return a VEX register offset from the pyvex boundary."""
    try:
        return _external_int_8616(cast(_VexExprBoundary8616, expr).offset)
    except (AttributeError, TypeError, ValueError):
        return None


def _expr_tmp_8616(expr: object) -> int | None:
    """Return a VEX temporary id from the pyvex boundary."""
    try:
        return _external_int_8616(cast(_VexExprBoundary8616, expr).tmp)
    except (AttributeError, TypeError, ValueError):
        return None


def _const_value_8616(expr: object | None) -> int | None:
    """Return a wrapped or bare VEX constant value from the boundary."""
    if expr is None:
        return None
    try:
        wrapped = cast(_VexExprBoundary8616, expr).con
    except AttributeError:
        wrapped = None
    if wrapped is not None:
        try:
            return _external_int_8616(cast(_VexConstBoundary8616, wrapped).value)
        except (AttributeError, TypeError, ValueError):
            return None
    try:
        return _external_int_8616(cast(_VexConstBoundary8616, expr).value)
    except (AttributeError, TypeError, ValueError):
        return None


def _resolve_tmp_8616(
    expr: object | None,
    tmp_exprs: Mapping[int, object],
    *,
    depth: int = 0,
) -> object | None:
    """Resolve a VEX temporary read to its recorded producer expression."""
    node = expr
    while _expr_tag_8616(node) == "Iex_RdTmp" and depth < _MAX_NEXT_ALIAS_DEPTH_8616:
        tmp_id = _expr_tmp_8616(node)
        if tmp_id is None:
            return node
        producer = tmp_exprs.get(tmp_id)
        if producer is None:
            return node
        node = producer
        depth += 1
    return node


def _match_unop_operand_8616(
    node: object | None,
    op: str,
    tmp_exprs: Mapping[int, object],
) -> object | None:
    """Match one ``Iex_Unop`` node and return its resolved sole operand."""
    node = _resolve_tmp_8616(node, tmp_exprs)
    if _expr_tag_8616(node) != "Iex_Unop" or _expr_op_8616(node) != op:
        return None
    args = _expr_args_8616(node)
    if len(args) != 1:
        return None
    return _resolve_tmp_8616(args[0], tmp_exprs)


def _match_binop_operands_8616(
    node: object | None,
    op: str,
    tmp_exprs: Mapping[int, object],
) -> tuple[object | None, object | None] | None:
    """Match one ``Iex_Binop`` node and return its resolved operand pair."""
    node = _resolve_tmp_8616(node, tmp_exprs)
    if _expr_tag_8616(node) != "Iex_Binop" or _expr_op_8616(node) != op:
        return None
    args = _expr_args_8616(node)
    if len(args) != 2:
        return None
    return (
        _resolve_tmp_8616(args[0], tmp_exprs),
        _resolve_tmp_8616(args[1], tmp_exprs),
    )


def _segment_base_register_8616(
    expr: object | None,
    tmp_exprs: Mapping[int, object],
    type_environment: object | None,
) -> str | None:
    """Match ``Shl32(16Uto32(GET:I16(seg)), 4)`` and return the register name."""
    operands = _match_binop_operands_8616(expr, "Iop_Shl32", tmp_exprs)
    if operands is None or _const_value_8616(operands[1]) != 4:
        return None
    leaf = _match_unop_operand_8616(operands[0], "Iop_16Uto32", tmp_exprs)
    if _expr_tag_8616(leaf) != "Iex_Get":
        return None
    offset = _expr_offset_8616(leaf)
    if offset is None:
        return None
    if vex_expr_size_bytes(leaf, type_environment=type_environment, default=0) != 2:
        return None
    return cast(str, register_name_from_offset(offset, size=2))


def _match_word_continuation_8616(
    widened: object | None,
    tmp_exprs: Mapping[int, object],
    type_environment: object | None,
) -> tuple[int, int, str] | None:
    """Match ``16Uto32(Add16(32to16(Sub32(next_linear, cs<<4)), disp16))``.

    Returns ``(next_linear, masked_displacement, segment)`` for the inner
    CS-relative continuation, or ``None`` when the operand is not that
    composition. The CS composition site is returned for the caller's
    second-site equality check.
    """
    add16 = _match_unop_operand_8616(widened, "Iop_16Uto32", tmp_exprs)
    operands = _match_binop_operands_8616(add16, "Iop_Add16", tmp_exprs)
    if operands is None:
        return None
    ip_base, displacement_expr = operands
    displacement = _const_value_8616(displacement_expr)
    if displacement is None or not 0 <= displacement <= 0xFFFF:
        return None
    narrowed = _match_unop_operand_8616(ip_base, "Iop_32to16", tmp_exprs)
    sub = _match_binop_operands_8616(narrowed, "Iop_Sub32", tmp_exprs)
    if sub is None:
        return None
    next_linear = _const_value_8616(sub[0])
    second_segment = _segment_base_register_8616(
        sub[1], tmp_exprs, type_environment,
    )
    if next_linear is None or second_segment is None:
        return None
    return next_linear, displacement, second_segment


def _match_next_shape_8616(
    next_expr: object | None,
    tmp_exprs: Mapping[int, object],
    type_environment: object | None,
) -> _NextShape8616 | None:
    """Match the lifter's control destination composition for ``next``.

    Word near jumps emit the ``control_coordinates.relative_continuation``
    composition ``Add32(cs<<4, 16Uto32(Add16(32to16(Sub32(next,cs<<4)),d)))``
    under the loader-linear domain. Operand-size-32 near jumps emit the flat
    ``Add32(next_linear, disp32)``; both constants are literal and the
    composition wraps exactly at the dword width, so no selector window is
    involved. Anything else is not a recognized composition.
    """
    node = _resolve_tmp_8616(next_expr, tmp_exprs)
    if _expr_tag_8616(node) != "Iex_Binop" or _expr_op_8616(node) != "Iop_Add32":
        return None
    args = _expr_args_8616(node)
    if len(args) != 2:
        return None
    left, right = args
    segment = _segment_base_register_8616(left, tmp_exprs, type_environment)
    if segment is not None:
        inner = _match_word_continuation_8616(
            _resolve_tmp_8616(right, tmp_exprs), tmp_exprs, type_environment,
        )
        if inner is None:
            return None
        next_linear, displacement, second_segment = inner
        return _NextShape8616(
            next_linear_addr=next_linear,
            displacement=displacement,
            segment_register=segment,
            second_segment_register=second_segment,
            control_bits=32,
        )
    left_const = _const_value_8616(_resolve_tmp_8616(left, tmp_exprs))
    right_const = _const_value_8616(_resolve_tmp_8616(right, tmp_exprs))
    if left_const is None or right_const is None:
        return None
    if not 0 <= left_const <= 0xFFFFFFFF or not 0 <= right_const <= 0xFFFFFFFF:
        return None
    return _NextShape8616(
        next_linear_addr=left_const,
        displacement=right_const,
        segment_register=None,
        second_segment_register=None,
        control_bits=32,
    )


def _signed_8616(value: int, bits: int) -> int:
    """Interpret a masked operand with its explicit sign, never modulo."""
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _target_fetch_invariant_8616(head: int, target: int) -> bool:
    """Require one target under every selector capable of fetching the head.

    A selector ``s`` can execute an instruction at loader-linear ``head``
    only when ``(s << 4) <= head <= (s << 4) + 0xFFFF``. When ``target``
    lies in the intersection of all such windows, the retained composition
    ``CS<<4 + ((next - CS<<4 + disp) mod 2^16)`` collapses to the same
    loader-linear value for every admissible CS, so the constant is proven
    by the fetch domain rather than assumed. The premise mirrors the shared
    selector-window contract used by the direct near-call binding proof.
    """
    minimum_selector = max(0, (head - 0xFFFF + 15) // 16)
    maximum_selector = min(0xFFFF, head // 16)
    return bool(
        minimum_selector <= maximum_selector
        and (maximum_selector << 4) <= target
        and target <= (minimum_selector << 4) + 0xFFFF
    )


def _block_bytes_8616(block: object) -> bytes | None:
    """Return the exact lifted byte string from the angr block boundary."""
    try:
        data = cast(_NativeBlockBoundary8616, block).bytes
    except AttributeError:
        return None
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    return None


def _block_size_8616(block: object) -> int | None:
    """Return the decoded byte size from the angr block boundary."""
    try:
        size = _external_int_8616(cast(_NativeBlockBoundary8616, block).size)
    except (AttributeError, TypeError, ValueError):
        return None
    return size if type(size) is int and size >= 0 else None


def _block_addr_8616(block: object) -> int | None:
    """Return the loader-linear base from the angr block boundary."""
    try:
        addr = _external_int_8616(cast(_NativeBlockBoundary8616, block).addr)
    except (AttributeError, TypeError, ValueError):
        return None
    return addr if type(addr) is int and addr >= 0 else None


def _terminal_encoding_8616(
    block: object,
    instruction_addr: int,
    instruction_size: int,
) -> bytes | None:
    """Slice the exact terminal instruction bytes the lifter decoded.

    The marked instruction must sit at the block tail: its offset within the
    lifted bytes must be exact, and its end must be the block end. Anything
    else means the bytes cannot prove a terminal transfer.
    """
    block_addr = _block_addr_8616(block)
    block_size = _block_size_8616(block)
    data = _block_bytes_8616(block)
    if block_addr is None or block_size is None or data is None:
        return None
    if len(data) != block_size:
        return None
    offset = instruction_addr - block_addr
    if offset < 0 or instruction_size <= 0 or offset + instruction_size > block_size:
        return None
    if offset + instruction_size != block_size:
        return None
    return data[offset : offset + instruction_size]


def _evidence_8616(
    *,
    retain: bool,
    proven_target: int | None,
    failure: TerminalJumpRefusalReason8616 | None,
    block_addr: int | None,
    classified: bool,
    detail: str,
    decoded: DecodedRelativeEdge | None = None,
) -> TerminalJumpEvidence8616:
    """Close the evidence decision with counts matching its typed outcome."""
    refusals: tuple[IRRefusal, ...] = ()
    if failure is not None:
        refusals = (
            IRRefusal(failure.value, detail or failure.value, block_addr),
        )
    return TerminalJumpEvidence8616(
        retain=retain,
        proven_target=proven_target,
        refusals=refusals,
        failure=failure,
        decoded=decoded,
        stats=TerminalJumpEvidenceStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=int(classified),
            materialized_count=int(proven_target is not None),
            failure_count=int(failure is not None),
        ),
    )


def terminal_direct_jump_evidence_8616(
    block: object,
    vex: object,
    *,
    instruction_addr: int | None,
    instruction_size: int | None,
    tmp_exprs: Mapping[int, object],
    type_environment: object | None = None,
) -> TerminalJumpEvidence8616:
    """Evaluate one ``Ijk_Boring`` block tail as a native direct jump.

    The jump is retained only when the exact terminal bytes decode to an
    unconditional near-relative form whose marked extent is the block tail.
    A loader-linear destination is published only when the ``next`` operand
    is the lifter's composition for the same decoded edge and the resulting
    target is invariant under the instruction's selector fetch window.
    Non-jump terminals and missing byte evidence return ``retain=False``
    with a closed zero classification; the instruction's IR effects already
    carry its semantics, so absence of the marker is not a dropped fact.
    """
    try:
        jumpkind = str(cast(_VexBlockBoundary8616, vex).jumpkind)
        next_expr = cast(_VexBlockBoundary8616, vex).next
    except AttributeError:
        jumpkind, next_expr = "", None
    block_addr = _block_addr_8616(block)
    if (
        jumpkind != "Ijk_Boring"
        or type(instruction_addr) is not int
        or instruction_addr < 0
        or type(instruction_size) is not int
    ):
        return TerminalJumpEvidence8616(
            retain=False,
            proven_target=None,
            refusals=(),
            failure=None,
            stats=TerminalJumpEvidenceStats8616(0, 0, 0, 0, 0),
        )
    encoding = _terminal_encoding_8616(block, instruction_addr, instruction_size)
    decoded = (
        None
        if encoding is None
        else decode_relative_edge(instruction_addr, encoding, source="block_terminal")
    )
    if not isinstance(decoded, DecodedRelativeEdge):
        return TerminalJumpEvidence8616(
            retain=False,
            proven_target=None,
            refusals=(),
            failure=None,
            stats=TerminalJumpEvidenceStats8616(1, 0, 0, 0, 0),
        )
    if decoded.form not in _UNCONDITIONAL_JUMP_FORMS_8616:
        return TerminalJumpEvidence8616(
            retain=False,
            proven_target=None,
            refusals=(),
            failure=None,
            stats=TerminalJumpEvidenceStats8616(1, 1, 0, 0, 0),
        )
    return _proven_terminal_target_8616(
        decoded, next_expr, tmp_exprs, type_environment, block_addr,
    )


def _proven_terminal_target_8616(
    decoded: DecodedRelativeEdge,
    next_expr: object | None,
    tmp_exprs: Mapping[int, object],
    type_environment: object | None,
    block_addr: int | None,
) -> TerminalJumpEvidence8616:
    """Prove the decoded jump's loader-linear destination or refuse it."""
    head = decoded.head
    linear_target = decoded.next_head + decoded.displacement
    constant_next = _const_value_8616(next_expr)
    if constant_next is not None:
        if constant_next == linear_target:
            return _evidence_8616(
                retain=True,
                proven_target=constant_next,
                failure=None,
                block_addr=block_addr,
                classified=True,
                detail="",
                decoded=decoded,
            )
        return _evidence_8616(
            retain=True,
            proven_target=None,
            failure=TerminalJumpRefusalReason8616.CONSTANT_CONFLICT,
            block_addr=block_addr,
            classified=True,
            detail=(
                f"constant next 0x{constant_next:x} disagrees with decoded "
                f"relative target 0x{linear_target:x}"
            ),
            decoded=decoded,
        )
    shape = _match_next_shape_8616(next_expr, tmp_exprs, type_environment)
    if shape is None:
        return _evidence_8616(
            retain=True,
            proven_target=None,
            failure=TerminalJumpRefusalReason8616.SHAPE_MISMATCH,
            block_addr=block_addr,
            classified=True,
            detail="next operand is not the lifter's near-relative composition",
            decoded=decoded,
        )
    if shape.control_bits != 32:
        return _evidence_8616(
            retain=True,
            proven_target=None,
            failure=TerminalJumpRefusalReason8616.NEXT_OPERAND_MALFORMED,
            block_addr=block_addr,
            classified=True,
            detail=f"control width {shape.control_bits} is not dword",
            decoded=decoded,
        )
    if shape.segment_register is not None and (
        shape.segment_register != _CS_SEGMENT_REGISTER_8616
        or shape.second_segment_register != shape.segment_register
    ):
        return _evidence_8616(
            retain=True,
            proven_target=None,
            failure=TerminalJumpRefusalReason8616.SEGMENT_DOMAIN_MISMATCH,
            block_addr=block_addr,
            classified=True,
            detail=f"control segment is {shape.segment_register!r}, not cs",
            decoded=decoded,
        )
    if shape.next_linear_addr != decoded.next_head:
        return _evidence_8616(
            retain=True,
            proven_target=None,
            failure=TerminalJumpRefusalReason8616.CONTINUATION_MISMATCH,
            block_addr=block_addr,
            classified=True,
            detail=(
                f"embedded continuation 0x{shape.next_linear_addr:x} does not "
                f"equal the decoded next head 0x{decoded.next_head:x}"
            ),
            decoded=decoded,
        )
    displacement_bits = (
        _WORD_OPERAND_BITS_8616
        if decoded.form in _WORD_JUMP_FORMS_8616
        else _DWORD_OPERAND_BITS_8616
    )
    if _signed_8616(
        shape.displacement & ((1 << displacement_bits) - 1), displacement_bits
    ) != decoded.displacement:
        return _evidence_8616(
            retain=True,
            proven_target=None,
            failure=TerminalJumpRefusalReason8616.DISPLACEMENT_MISMATCH,
            block_addr=block_addr,
            classified=True,
            detail=(
                f"embedded displacement 0x{shape.displacement:x} does not "
                f"equal the decoded displacement {decoded.displacement}"
            ),
            decoded=decoded,
        )
    if decoded.form in _WORD_JUMP_FORMS_8616:
        if not _target_fetch_invariant_8616(head, linear_target):
            return _evidence_8616(
                retain=True,
                proven_target=None,
                failure=TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED,
                block_addr=block_addr,
                classified=True,
                detail=(
                    f"decoded target 0x{linear_target:x} is not invariant "
                    f"across the fetch window of 0x{head:x}"
                ),
                decoded=decoded,
            )
        target = linear_target
    else:
        target = linear_target & 0xFFFFFFFF
    return _evidence_8616(
        retain=True,
        proven_target=target,
        failure=None,
        block_addr=block_addr,
        classified=True,
        detail="",
        decoded=decoded,
    )
