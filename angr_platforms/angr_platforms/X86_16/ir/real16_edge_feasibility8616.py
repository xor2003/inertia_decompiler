"""Bounded known-bits edge feasibility for the real-mode invocation census.

Layer: IR (invocation/control proof).
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.

Responsibility: before the instruction-level census demands closure for
every syntactic path callee, establish — under the identical authenticated
seed, fetched-byte binding, and declared-service application — which CFG
edges are *provably* untraversable on this exact invocation. The proof is
a forward must-meet known-bits abstract interpretation over the same
authoritative typed IR rows the census simulates; branch verdicts evaluate
the lifted ``IRCondition`` semantics only — no machine-opcode or flag
reinterpretation is performed here. An edge is excluded from the live
census scope **only** when its successor choice is proven under the
converged must-state; every unknown verdict keeps the edge and its
call/effect obligations. No raw IR is deleted, no callee preservation is
published, and the verdict is scoped to this one authenticated
invocation — it is not a universal dead-code claim.

The known-bits domain tracks ``(known_mask, known_value)`` per register
lane and tmp: a bit is proven only when every contributing path agrees.
This is strictly more precise than the all-or-nothing integer dictionary
the effect census uses: ``flags = (old & keep_mask) | computed`` leaves
the carry bit proven even when unrelated flag bits are unknown, which is
exactly the precision an ``ADD``-then-``Jcc`` bound prefix needs.

Memory writes are path facts in the same must-meet discipline: every
abstract state pairs the register/tmp lattice with the shared
``PathMemory8616`` byte overlay from ``real16_path_memory8616``. STORE
rows are no longer skipped — a proven span and proven data become known
bytes, a proven span with unproven data becomes unknown bytes, and an
unevaluated span or an unbounded boundary taints the whole overlay. The
declared-service hook therefore sees *current* path metadata, never the
initial image bytes: a resize crossing may only publish its constants
when the path memory proves the MCB bytes it reads.

Consumption contract for the caller (``_census_invocation_8616``): run
after the fetched-byte census has bound ``machine_bytes`` for every
dangerous block, before ``_census_path_callees_8616`` and before
``_simulate_scope_8616``; restrict both to ``live_blocks``. Byte binding,
the store manifest, and the row ledger stay over the full syntactic cone
so no reachable byte obligation is silently dropped.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass

from ..semantics.register_value_preservation import (
    register_value_family_8616,
    register_value_projection_8616,
)
from .condition_ir import normalize_condition_op_8616
from .core import (
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)
from .real16_declared_interrupt8616 import interrupt_call_vector_8616
from .real16_path_memory8616 import (
    SEGMENT_BASE_NAME_8616,
    SEGMENT_SHIFT_8616,
    PathMemory8616,
    meet_path_memory_8616,
    path_memory_tainted_8616,
    store_atom_clean_8616,
)
from .real16_wide_multiply8616 import wide_multiply_shape_8616, wide_multiply_value_8616
from .scalar_instruction_effects import (
    ScalarInstructionClobber8616,
    ScalarInstructionEffectKind8616,
    scalar_instruction_effect_8616,
)

__all__ = [
    "Real16EdgeFeasibility8616",
    "invocation_feasible_scope_8616",
]

from .real16_repeated_store8616 import RepeatedStoreStatus8616

# A known-bits lattice element: ``(known_mask, known_value)``. A bit of
# ``known_value`` is meaningful only where ``known_mask`` is set.
_Kb8616 = tuple[int, int]
_KbRegs8616 = dict[str, _Kb8616]
_KbTmps8616 = dict[int, _Kb8616]
# A fully-known 16-bit lane mask; address arithmetic in this domain is
# word-wide.
_KB_WORD_MASK_8616 = 0xFFFF
# Precision refinement is bounded independently of each must-state fixpoint.
_EDGE_REFINEMENT_ROUND_LIMIT_8616: int = 8

_CONVERSION_OP_8616 = re.compile(r"^Iop_(\d+)(U|S)?to(\d+)$")
_BINOP_8616 = re.compile(r"^Iop_([A-Za-z]+?)(\d+)([US])?$")
# ``Iop_`` names that real VEX emits only from ``Iex_Binop``. Such a tag
# on a ``source_tmp``-pinned value is always producer provenance — the
# importer's Unop boundary never carries them — so the pinned-view
# ambiguity below exists only for the remaining unary-family tags.
_BINOP_TAG_8616 = re.compile(
    r"^Iop_(Add|Sub|Mul|And|Or|Xor|Shl|Shr|Sar"
    r"|CmpEQ|CmpNE|CmpLT|CmpLE|CmpGT|CmpGE)\d+[US]?$"
)


@dataclass(frozen=True, slots=True)
class Real16EdgeFeasibility8616:
    """Typed per-edge feasibility result for one invocation census scope.

    ``infeasible_edges`` names ``(block_addr, successor_addr)`` pairs whose
    traversal is *proven impossible* under the converged must-state of this
    exact invocation; it stays empty unless the fixpoint converged.
    ``live_blocks`` is the dangerous cone recomputed under the surviving
    edges — identical to the input scope whenever no edge was proven dead.
    ``evaluated_cjmps``/``proven_edges`` count the verdicts so receipts can
    distinguish "no conditional edge examined" from "examined, unproven".
    ``converged`` records whether the retained dataflow round completed,
    not whether every possible refinement was discovered. If a later round
    exhausts its budget, only earlier fully completed rounds remain published;
    the incomplete round contributes no facts. With no completed round,
    ``converged`` is false and no pruning is published.
    ``evaluated_cjmps`` counts observations in committed rounds, including
    re-evaluations. ``work_units``
    reports how much abstract work the caller should charge to its own
    census budget.
    """

    live_blocks: frozenset[int]
    infeasible_edges: tuple[tuple[int, int], ...]
    evaluated_cjmps: int
    proven_edges: int
    converged: bool
    work_units: int


def _kb_width_mask_8616(size: object) -> int | None:
    """Return the wrap mask for one byte width, else ``None``."""
    if type(size) is not int or size not in (1, 2, 4, 8):
        return None
    return (1 << (size * 8)) - 1


def _kb_lowest_unknown_8616(mask: int, width_mask: int) -> int:
    """Return the count of contiguous known low bits inside ``width_mask``."""
    unknown = (~mask) & width_mask
    if unknown == 0:
        return width_mask.bit_length()
    return (unknown & -unknown).bit_length() - 1


def _kb_add_8616(a: _Kb8616, b: _Kb8616, width_mask: int) -> _Kb8616:
    """Add two known-bits values: result bits stay known below the lowest
    unknown operand bit because carries only ripple upward."""
    boundary = min(
        _kb_lowest_unknown_8616(a[0], width_mask),
        _kb_lowest_unknown_8616(b[0], width_mask),
    )
    mask = ((1 << boundary) - 1) & width_mask
    return (mask, (a[1] + b[1]) & mask)


def _kb_sub_8616(a: _Kb8616, b: _Kb8616, width_mask: int) -> _Kb8616:
    """Subtract with the same upward-ripple known-bit bound as addition."""
    boundary = min(
        _kb_lowest_unknown_8616(a[0], width_mask),
        _kb_lowest_unknown_8616(b[0], width_mask),
    )
    mask = ((1 << boundary) - 1) & width_mask
    return (mask, (a[1] - b[1]) & mask)


def _kb_and_8616(a: _Kb8616, b: _Kb8616, width_mask: int) -> _Kb8616:
    """Bitwise AND: a bit is known when either side is known-zero or both
    sides are known."""
    mask = (((~a[1]) & a[0]) | ((~b[1]) & b[0]) | (a[0] & b[0])) & width_mask
    return (mask, (a[1] & b[1]) & mask)


def _kb_or_8616(a: _Kb8616, b: _Kb8616, width_mask: int) -> _Kb8616:
    """Bitwise OR: a bit is known when either side is known-one or both
    sides are known."""
    mask = ((a[1] & a[0]) | (b[1] & b[0]) | (a[0] & b[0])) & width_mask
    return (mask, (a[1] | b[1]) & mask)


def _kb_xor_8616(a: _Kb8616, b: _Kb8616, width_mask: int) -> _Kb8616:
    """Bitwise XOR: a bit is known only when both sides are known."""
    mask = (a[0] & b[0]) & width_mask
    return (mask, (a[1] ^ b[1]) & mask)


def _kb_not_8616(a: _Kb8616, width_mask: int) -> _Kb8616:
    """Bitwise NOT preserves exactly the known bits."""
    return (a[0] & width_mask, (~a[1]) & a[0] & width_mask)


def _kb_shift_8616(
    a: _Kb8616, b: _Kb8616, width_mask: int, left: bool, count_bits: int | None
) -> _Kb8616:
    """Shift by a fully-known amount; unknown amounts stay unknown.

    The count operand carries its own authoritative width — VEX shifts
    use an 8-bit count regardless of the data width — so the count is
    fully known iff its known mask covers exactly its declared width,
    never the result width. Vacated bits enter as proven zeros: a left
    shift's low ``count`` bits and a logical right shift's high ``count``
    bits are known-zero in the result.
    """
    if count_bits is None or count_bits <= 0:
        return (0, 0)
    count_mask = (1 << count_bits) - 1
    if b[0] != count_mask:
        return (0, 0)
    bits = width_mask.bit_length()
    count = b[1] & count_mask
    if count >= bits:
        return (width_mask, 0)
    if left:
        fill = (1 << count) - 1
        return (
            ((a[0] << count) | fill) & width_mask,
            (a[1] << count) & width_mask,
        )
    fill = ((1 << count) - 1) << (bits - count)
    return ((a[0] >> count) | (fill & width_mask), (a[1] >> count) & width_mask)


def _kb_cmp_eq_8616(a: _Kb8616, b: _Kb8616, width_mask: int) -> _Kb8616:
    """Equality: proven when both sides are known, disproven on any known
    bit disagreement."""
    if a[0] == width_mask and b[0] == width_mask:
        return (1, 1 if a[1] == b[1] else 0)
    if (a[0] & b[0]) & (a[1] ^ b[1]):
        return (1, 0)
    return (0, 0)


def _kb_cmp_ne_8616(a: _Kb8616, b: _Kb8616, width_mask: int) -> _Kb8616:
    """Inequality mirrors equality with the result bit inverted."""
    equal = _kb_cmp_eq_8616(a, b, width_mask)
    return (equal[0], 1 - equal[1]) if equal[0] else equal


def _kb_cmp_order_8616(
    name: str, a: _Kb8616, b: _Kb8616, width_mask: int, signed: bool
) -> _Kb8616:
    """Ordered comparisons need both operands fully known."""
    if a[0] != width_mask or b[0] != width_mask:
        return (0, 0)
    bits = width_mask.bit_length()
    left: int = a[1]
    right: int = b[1]
    if signed:
        sign = 1 << (bits - 1)
        left -= (left & sign) << 1
        right -= (right & sign) << 1
    result = {
        "CmpLT": left < right,
        "CmpLE": left <= right,
        "CmpGT": left > right,
        "CmpGE": left >= right,
    }.get(name)
    return (0, 0) if result is None else (1, int(result))


def _kb_mul_8616(a: _Kb8616, b: _Kb8616, width_mask: int) -> _Kb8616:
    """Product bit i depends only on operand bits 0..i — the same upward
    dependency bound as addition, applied to the product value."""
    boundary = min(
        _kb_lowest_unknown_8616(a[0], width_mask),
        _kb_lowest_unknown_8616(b[0], width_mask),
    )
    mask = ((1 << boundary) - 1) & width_mask
    return (mask, (a[1] * b[1]) & mask)


_KB_BINOP_PLAIN_8616: dict[str, Callable[[_Kb8616, _Kb8616, int], _Kb8616]] = {
    "Add": _kb_add_8616,
    "Sub": _kb_sub_8616,
    "Mul": _kb_mul_8616,
    "And": _kb_and_8616,
    "Or": _kb_or_8616,
    "Xor": _kb_xor_8616,
    "CmpEQ": _kb_cmp_eq_8616,
    "CmpNE": _kb_cmp_ne_8616,
}


def _kb_binary_op_8616(
    op: str, a: _Kb8616, b: _Kb8616, count_bits: int | None = None, *,
    operands: tuple[object, object] | None = None, result_size: int | None = None,
) -> _Kb8616 | None:
    """Apply one exact-whitelisted VEX integer binop in known-bits form.

    The whitelist deliberately matches the effect census's own table plus
    the comparison forms the lifter emits for flag materialization;
    anything else evaluates to unknown rather than guessing semantics.
    ``count_bits`` is the shift-count operand's own authoritative bit
    width; shifts without it evaluate to unknown.
    """
    shape = wide_multiply_shape_8616(op)
    if shape is not None:
        bits, _signed = shape
        if a[0] != (1 << bits) - 1 or b[0] != (1 << bits) - 1:
            return None
        value = wide_multiply_value_8616(op, a[1], b[1], operands, result_size)
        return None if value is None else ((1 << (bits * 2)) - 1, value)
    match = _BINOP_8616.fullmatch(op)
    if match is None:
        return None
    name, digits, signed_suffix = match.groups()
    width_mask = (1 << int(digits)) - 1
    plain = _KB_BINOP_PLAIN_8616.get(name)
    if plain is not None:
        return plain(a, b, width_mask)
    if name in ("Shl", "Shr"):
        return _kb_shift_8616(a, b, width_mask, name == "Shl", count_bits)
    if name in ("CmpLT", "CmpLE", "CmpGT", "CmpGE"):
        return _kb_cmp_order_8616(name, a, b, width_mask, signed_suffix == "S")
    return None


def _kb_unary_op_8616(op: str, a: _Kb8616) -> _Kb8616 | None:
    """Apply a whitelisted unary op (``Iop_Not<width>`` only)."""
    match = _BINOP_8616.fullmatch(op)
    if match is None or match.group(1) != "Not":
        return None
    return _kb_not_8616(a, (1 << int(match.group(2))) - 1)


_HITO_OP_8616 = re.compile(r"^Iop_(\d+)HIto(\d+)$")
_UNARY_NOT_OP_8616 = re.compile(r"^Iop_Not(\d+)$")
# Bound on nested active-unary evaluation; genuine VEX chains are shallow.
_UNARY_DEPTH_LIMIT_8616 = 8


def _kb_unary_evidence_8616(
    op: str, a: _Kb8616, result_bits: int
) -> _Kb8616 | None:
    """Apply one authoritative ``active_unary`` op in known-bits form.

    Mirrors ``_eval_unary_op_8616`` over the known-bits lattice:
    ``Not`` preserves exactly the known bits, truncation drops the high
    known bits, zero extension marks vacated bits known-zero, sign
    extension projects them only when the sign bit is proven, and
    ``<2n>HIto<n>`` shifts the operand's known bits down. The op's
    declared result width must equal ``result_bits``; anything else is
    unknown.
    """
    if type(result_bits) is not int or result_bits <= 0:
        return None
    not_match = _UNARY_NOT_OP_8616.fullmatch(op)
    if not_match is not None:
        bits = int(not_match.group(1))
        if bits != result_bits:
            return None
        return _kb_not_8616(a, (1 << bits) - 1)
    hi_match = _HITO_OP_8616.fullmatch(op)
    if hi_match is not None:
        src_bits = int(hi_match.group(1))
        dst_bits = int(hi_match.group(2))
        if dst_bits != result_bits or src_bits != 2 * dst_bits:
            return None
        dst_mask = (1 << dst_bits) - 1
        return ((a[0] >> dst_bits) & dst_mask, (a[1] >> dst_bits) & dst_mask)
    match = _CONVERSION_OP_8616.fullmatch(op)
    if match is None:
        return None
    dst_bits = int(match.group(3))
    if dst_bits != result_bits:
        return None
    return _kb_convert_token_8616(op, a[0], a[1])


def _kb_expr_provenance_only_8616(value: IRValue) -> bool:
    """Return whether an unpinned value's ``expr`` is safe provenance.

    Binary-fold tags describe an already-folded displacement; non-``Iop_``
    markers (``load``, ``condition_tmp``, operand names) are provenance.
    Any other ``Iop_*`` token claims a unary transformation without typed
    ``active_unary`` evidence — an unverifiable projection that must not
    silently evaluate as the raw register value.
    """
    for token in value.expr or ():
        if not token.startswith("Iop_"):
            continue
        if _BINOP_TAG_8616.fullmatch(token) is None:
            return False
    return True


def _kb_convert_token_8616(
    token: str, mask: int, result: int
) -> tuple[int, int] | None:
    """Apply one width-conversion ``expr`` token, or ``None`` when the
    token is not a conversion. The declared input width bounds what the
    conversion consumes — truncate first, then extend."""
    match = _CONVERSION_OP_8616.fullmatch(token)
    if match is None:
        return None
    src_bits = int(match.group(1))
    dst_bits = int(match.group(3))
    sign = match.group(2)
    dst_mask = (1 << dst_bits) - 1
    src_mask = (1 << src_bits) - 1
    mask &= src_mask
    result &= src_mask
    if src_bits > dst_bits:
        mask &= dst_mask
        result &= dst_mask
    elif sign == "S":
        upper = dst_mask & ~src_mask
        if mask & (1 << (src_bits - 1)):
            mask |= upper
            if result & (1 << (src_bits - 1)):
                result |= upper
        else:
            mask &= src_mask
            result &= src_mask
    elif sign == "U":
        mask |= dst_mask & ~src_mask
        result &= dst_mask
    else:
        # A bare ``<src>to<dst>`` widening has no signedness — not a real
        # VEX op shape — so it cannot authorize known-zero high bits.
        return None
    mask &= dst_mask
    result &= mask
    return (mask, result)


def _kb_read_register_8616(name: str, regs: _KbRegs8616) -> _Kb8616 | None:
    """Read one register view, recomposing wider views from stored lanes.

    Mirrors the effect census's lane tiling: every known bit of the
    requested view must be covered by family members that know it;
    overlapping contributors that disagree revoke only the shared bits.
    """
    projection = register_value_projection_8616(name, name)
    if projection is None:
        return None
    view_mask = (1 << projection[1]) - 1
    covered = 0
    value = 0
    for member in register_value_family_8616(name):
        lane = register_value_projection_8616(name, member)
        if lane is None:
            continue
        stored = regs.get(member)
        if stored is None:
            continue
        shift, bits = lane
        lane_mask = ((1 << bits) - 1) << shift
        contrib_mask = (stored[0] << shift) & lane_mask
        contrib_value = (stored[1] << shift) & lane_mask
        conflict = covered & contrib_mask & (value ^ contrib_value)
        covered |= contrib_mask & ~conflict
        value |= contrib_value
    if covered == 0:
        return None
    return (covered & view_mask, value & covered & view_mask)


def _kb_write_register_8616(
    name: str, dst_size: object, kb: _Kb8616 | None, regs: _KbRegs8616
) -> None:
    """Apply one register write through the lane model in known-bits form.

    Mirrors ``_apply_register_write_8616``: members fully contained in the
    written view are re-projected (only proven bits propagate); members
    containing the view keep their outside bits; disjoint lanes are
    untouched. An unknown or width-mismatched write drops only the written
    bits — a partially-known write preserves exactly its proven coverage.
    """
    projection = register_value_projection_8616(name, name)
    width = None if projection is None else projection[1]
    if (
        kb is not None
        and width is not None
        and type(dst_size) is int
        and dst_size * 8 == width
    ):
        name_mask = (1 << width) - 1
        known = (kb[0] & name_mask, kb[1] & name_mask)
    else:
        known = (0, 0)
    for member in register_value_family_8616(name):
        if member == name:
            continue
        contained = register_value_projection_8616(name, member)
        contains = register_value_projection_8616(member, name)
        if contained is not None:
            shift, bits = contained
            lane_mask = (1 << bits) - 1
            member_kb = (
                (known[0] >> shift) & lane_mask,
                (known[1] >> shift) & lane_mask,
            )
            if member_kb[0]:
                regs[member] = member_kb
            else:
                regs.pop(member, None)
        elif contains is not None:
            shift, bits = contains
            member_projection = register_value_projection_8616(member, member)
            if member_projection is None:
                continue
            overlay_mask = ((1 << bits) - 1) << shift
            member_mask = (1 << member_projection[1]) - 1
            old = regs.get(member, (0, 0))
            member_kb = (
                ((old[0] & ~overlay_mask) | ((known[0] << shift) & overlay_mask))
                & member_mask,
                ((old[1] & ~overlay_mask) | ((known[1] << shift) & overlay_mask))
                & member_mask,
            )
            if member_kb[0]:
                regs[member] = member_kb
            else:
                regs.pop(member, None)
    if known[0]:
        regs[name] = known
    else:
        regs.pop(name, None)


def _kb_eval_value_8616(
    value: object,
    regs: _KbRegs8616,
    tmps: _KbTmps8616,
    depth: int = 0,
) -> _Kb8616 | None:
    """Evaluate one typed IR value in known-bits form.

    A ``source_tmp`` pin names an *immutable capture*: ``RdTmp``-imported
    references carry the stored view of the producer's tmp, so the value
    is exactly the tmp's evaluated result — reading the named register
    instead would observe a newer value, and the view's ``offset``/
    ``expr`` are producer provenance that must never be replayed. Typed
    ``active_unary`` evidence is evaluated recursively on its own operand
    first; a pin combined with active evidence is contradictory and
    refuses. Without either, ``expr`` must be pure provenance
    (``_kb_expr_provenance_only_8616``); constants are exact and register
    views read the abstract state plus their folded displacement.
    """
    if depth > _UNARY_DEPTH_LIMIT_8616:
        return None
    if not isinstance(value, IRValue):
        return None
    if value.index is not None or value.index_shift:
        return None
    if value.source_tmp is not None:
        if value.active_unary is not None:
            return None
        return _kb_fit_width_8616(value.size, tmps.get(value.source_tmp))
    if value.active_unary is not None:
        operand = _kb_eval_value_8616(
            value.active_unary.operand, regs, tmps, depth + 1
        )
        if operand is None:
            return None
        return _kb_unary_evidence_8616(
            value.active_unary.op, operand, value.active_unary.result_bits
        )
    return _kb_eval_plain_8616(value, regs)


def _kb_eval_plain_8616(
    value: IRValue, regs: _KbRegs8616
) -> _Kb8616 | None:
    """Evaluate a provenance-only CONST/REG view plus folded displacement.

    ``expr`` must be pure provenance (``_kb_expr_provenance_only_8616``);
    the folded ``offset`` is added at the declared byte width.
    """
    if not _kb_expr_provenance_only_8616(value):
        return None
    if value.space is MemSpace.CONST:
        const_mask = _kb_width_mask_8616(value.size)
        base = (
            None
            if const_mask is None or type(value.const) is not int
            else (const_mask, value.const & const_mask)
        )
    elif value.space is MemSpace.REG:
        base = (
            None
            if value.name is None
            else _kb_read_register_8616(value.name, regs)
        )
    else:
        return None
    base = _kb_fit_width_8616(value.size, base)
    if base is not None and value.offset:
        width_mask = _kb_width_mask_8616(value.size)
        if width_mask is None:
            return None
        base = _kb_add_8616(
            base, (width_mask, value.offset & width_mask), width_mask
        )
    return base


def _kb_fit_width_8616(size: object, kb: _Kb8616 | None) -> _Kb8616 | None:
    """Mask a looked-up value to its declared byte width."""
    if kb is None:
        return None
    mask = _kb_width_mask_8616(size)
    if mask is None:
        return None
    return (kb[0] & mask, kb[1] & mask)


def _kb_seed_state_8616(seed: Mapping[str, int]) -> _KbRegs8616:
    """Convert the census's integer register seed into fully-known lanes."""
    state: _KbRegs8616 = {}
    for name, value in seed.items():
        projection = register_value_projection_8616(name, name)
        if projection is None or type(value) is not int:
            continue
        width = projection[1]
        state[name] = ((1 << width) - 1, value & ((1 << width) - 1))
    return state


def _kb_meet_8616(states: Iterable[_KbRegs8616]) -> _KbRegs8616:
    """Must-meet register states: a bit survives only when every path
    knows it and agrees on its value."""
    iterator = iter(states)
    try:
        merged = dict(next(iterator))
    except StopIteration:
        return {}
    for state in iterator:
        for name in tuple(merged):
            theirs = state.get(name)
            if theirs is None:
                del merged[name]
                continue
            mine = merged[name]
            shared = mine[0] & theirs[0] & ~(mine[1] ^ theirs[1])
            if shared:
                merged[name] = (shared, mine[1] & shared)
            else:
                del merged[name]
    return merged


@dataclass(slots=True)
class _KbPathState8616:
    """One feasibility path position: known-bits registers + path memory.

    The pair is the complete abstract state the fixpoint meets and the
    block transfer mutates — a register bit and a memory byte are proven
    under the identical per-predecessor must discipline, so a STORE on
    one arm can never be hidden by another arm's overwrite order.
    """

    registers: _KbRegs8616
    memory: PathMemory8616


def _kb_meet_state_8616(
    states: Iterable[_KbPathState8616],
) -> _KbPathState8616:
    """Meet whole path states componentwise under the must discipline."""
    items = list(states)
    return _KbPathState8616(
        registers=_kb_meet_8616(state.registers for state in items),
        memory=meet_path_memory_8616(state.memory for state in items),
    )


def _kb_known_registers_8616(regs: _KbRegs8616) -> dict[str, int]:
    """Project the fully-known register lanes for the declared-service
    crossing, which consumes the integer register dictionary."""
    known: dict[str, int] = {}
    for name, (mask, value) in regs.items():
        projection = register_value_projection_8616(name, name)
        if projection is not None and mask == (1 << projection[1]) - 1:
            known[name] = value
    return known


def _kb_poison_destination_8616(
    instruction: IRInstr,
    regs: _KbRegs8616,
    tmps: _KbTmps8616,
    dirty: set[str],
    entry: _KbRegs8616,
) -> None:
    """Conservatively drop the storage an unsupported row may write.

    Rows the feasibility evaluator cannot model correspond to rows the
    real census refuses outright, so the poisoned state can only keep
    edges alive — never prove one dead. Register destinations drop via
    the lane model and mark the instruction-entry snapshot dirty; tmp
    destinations drop the tmp; register-less unknown shapes clear
    everything because their clobber is unbounded, and every lane the
    entry snapshot still proves is dirty — a later same-instruction
    store must not read it as an entry value.
    """
    dst = instruction.dst
    if isinstance(dst, IRValue) and dst.space is MemSpace.REG and dst.name:
        _kb_write_register_8616(dst.name, dst.size, None, regs)
        _kb_dirty_write_8616(dst.name, dirty)
    elif isinstance(dst, IRValue) and dst.space is MemSpace.TMP:
        if dst.source_tmp is not None:
            tmps.pop(dst.source_tmp, None)
    else:
        regs.clear()
        tmps.clear()
        _kb_dirty_all_8616(entry, dirty)


def _kb_dirty_write_8616(name: str, dirty: set[str]) -> None:
    """Mark the register lanes one row wrote inside this instruction.

    Mirrors the census's ``_apply_register_write_8616`` dirty discipline:
    every family member overlapping the written view becomes unreadable
    through the instruction-entry snapshot, so a later STORE row in the
    same machine instruction never evaluates against a stale constant.
    """
    for member in register_value_family_8616(name):
        if member == name:
            continue
        if (
            register_value_projection_8616(name, member) is None
            and register_value_projection_8616(member, name) is None
        ):
            continue
        dirty.add(member)
    dirty.add(name)


def _kb_dirty_all_8616(entry: _KbRegs8616, dirty: set[str]) -> None:
    """Dirty every proven lane — an unbounded clobber may write any of them."""
    for name in tuple(entry):
        dirty.update(register_value_family_8616(name))


def _kb_eval_base_8616(
    value: object,
    entry: _KbRegs8616,
    dirty: set[str],
    tmps: _KbTmps8616,
    depth: int = 0,
) -> int | None:
    """Evaluate one captured address base to a concrete 16-bit value.

    Mirrors the census's ``_eval_base_value_8616`` over the known-bits
    lattice: ``source_tmp`` pins read the capture, ``active_unary``
    applies its typed op to the recursively evaluated operand, plain
    REG reads come from the instruction-entry snapshot and refuse dirty
    names, and CONST folds its displacement. Unlike the register walk,
    only a fully-proven value is useful — a partially-known address bit
    cannot bound a written span.
    """
    if depth > _UNARY_DEPTH_LIMIT_8616:
        return None
    if (
        not isinstance(value, IRValue)
        or value.index is not None
        or value.index_shift
        or type(value.offset) is not int
    ):
        return None
    if value.source_tmp is not None:
        if value.active_unary is not None:
            return None
        kb = tmps.get(value.source_tmp)
        return None if kb is None or kb[0] != _KB_WORD_MASK_8616 else kb[1]
    if value.active_unary is not None:
        operand = _kb_eval_base_8616(
            value.active_unary.operand, entry, dirty, tmps, depth + 1
        )
        if operand is None or type(value.active_unary.result_bits) is not int:
            return None
        kb = _kb_unary_evidence_8616(
            value.active_unary.op,
            (_KB_WORD_MASK_8616, operand),
            value.active_unary.result_bits,
        )
        full = (1 << value.active_unary.result_bits) - 1
        return None if kb is None or kb[0] != full else kb[1] & _KB_WORD_MASK_8616
    return _kb_eval_base_plain_8616(value, entry, dirty)


def _kb_eval_base_plain_8616(
    value: IRValue, entry: _KbRegs8616, dirty: set[str],
) -> int | None:
    """Read a provenance-only base from the unchanged instruction-entry state."""
    if not _kb_expr_provenance_only_8616(value) or type(value.offset) is not int:
        return None
    if value.space is MemSpace.REG and value.name is not None:
        if value.name in dirty:
            return None
        kb = _kb_read_register_8616(value.name, entry)
        return (
            None
            if kb is None or kb[0] != _KB_WORD_MASK_8616
            else (kb[1] + value.offset) & _KB_WORD_MASK_8616
        )
    if value.space is MemSpace.CONST and type(value.const) is int:
        return value.const + value.offset
    return None


def _kb_store_span_8616(
    instruction: IRInstr,
    address: object,
    entry: _KbRegs8616,
    dirty: set[str],
    tmps: _KbTmps8616,
) -> tuple[int, int] | None:
    """Resolve one STORE's exact linear [base, base+size) in kb form.

    Mirrors ``_store_span_8616`` under the identical instruction-entry
    snapshot and dirty-name discipline; every component must be fully
    proven or the span is unbounded.
    """
    if not isinstance(address, IRAddress) or type(address.offset) is not int:
        return None
    size = (
        address.size
        if type(address.size) is int and address.size > 0
        else instruction.size
    )
    if type(size) is not int or size <= 0:
        return None
    if address.space is MemSpace.UNKNOWN:
        # A bare constant address is the only segment-free form: the
        # offset is already the physical linear target.
        if (
            address.base
            or address.base_values
            or address.expr != ("absolute_const",)
        ):
            return None
        return address.offset, size
    segment = SEGMENT_BASE_NAME_8616.get(address.space)
    if segment is None or segment in dirty:
        return None
    segment_kb = _kb_read_register_8616(segment, entry)
    if segment_kb is None or segment_kb[0] != _KB_WORD_MASK_8616:
        return None
    bases = address.base_values or tuple(
        IRValue(MemSpace.REG, name=name, size=2) for name in address.base
    )
    offset_total = 0
    for value in bases:
        base_value = _kb_eval_base_8616(value, entry, dirty, tmps)
        if base_value is None:
            return None
        offset_total += base_value
    offset16 = (offset_total + address.offset) & _KB_WORD_MASK_8616
    return (segment_kb[1] << SEGMENT_SHIFT_8616) + offset16, size


def _kb_eval_atom_8616(
    atom: object,
    regs: _KbRegs8616,
    tmps: _KbTmps8616,
) -> _Kb8616 | None:
    """Evaluate one typed atom in known-bits form, or ``None``."""
    if isinstance(atom, IRValue):
        return _kb_eval_value_8616(atom, regs, tmps)
    if isinstance(atom, IRBinaryValue):
        left = _kb_eval_atom_8616(atom.lhs, regs, tmps)
        right = _kb_eval_atom_8616(atom.rhs, regs, tmps)
        if left is None or right is None:
            return None
        count_bits = (
            atom.rhs.size * 8
            if isinstance(atom.rhs, IRValue) and type(atom.rhs.size) is int
            else None
        )
        return _kb_binary_op_8616(
            atom.op, left, right, count_bits,
            operands=(atom.lhs, atom.rhs), result_size=atom.size,
        )
    return None


def _kb_store_data_8616(
    instruction: IRInstr,
    entry: _KbRegs8616,
    dirty: set[str],
    tmps: _KbTmps8616,
    size: int,
) -> bytes | None:
    """Return the exact bytes one STORE writes, or ``None``.

    Mirrors ``_store_data_bytes_8616``: the atom is evaluated under the
    instruction-entry snapshot with the shared dirty-name cleanliness
    rule; anything not fully proven — a memory read, an unknown tmp, a
    register modified inside this machine instruction — records
    ``None`` (span proven, bytes unknown) instead of a guessed constant.
    """
    atom = instruction.args[1]
    if not store_atom_clean_8616(atom, dirty):
        return None
    kb = _kb_eval_atom_8616(atom, entry, tmps)
    full = _kb_width_mask_8616(size)
    if kb is None or full is None or kb[0] != full:
        return None
    return (kb[1] & full).to_bytes(size, "little")


def _kb_store_row_8616(
    instruction: IRInstr,
    entry: _KbRegs8616,
    dirty: set[str],
    tmps: _KbTmps8616,
    memory: PathMemory8616,
) -> None:
    """Track one STORE row in the path memory overlay.

    A store the lattice cannot fully prove taints the whole overlay — an
    unevaluated span may have written anywhere, and a pruned-edge verdict
    must never depend on unproven memory. A proven span records its
    bytes; unproven data records unknown contents, never initial bytes.
    """
    if len(instruction.args) != 2 or instruction.dst is not None:
        memory.taint()
        return
    span = _kb_store_span_8616(
        instruction, instruction.args[0], entry, dirty, tmps
    )
    if span is None:
        memory.taint()
        return
    base, size = span
    memory.apply_write(
        base, size, _kb_store_data_8616(instruction, entry, dirty, tmps, size)
    )


def _kb_tmp_write_8616(
    instruction: IRInstr,
    dst: IRValue,
    regs: _KbRegs8616,
    tmps: _KbTmps8616,
) -> None:
    """Evaluate one tmp-producing row in known-bits form."""
    if dst.source_tmp is None:
        return
    evaluated: _Kb8616 | None = None
    if instruction.op == "MOV" and len(instruction.args) == 1:
        evaluated = _kb_eval_value_8616(instruction.args[0], regs, tmps)
    elif instruction.op.startswith("Iop_") and len(instruction.args) == 2:
        left = _kb_eval_value_8616(instruction.args[0], regs, tmps)
        right = _kb_eval_value_8616(instruction.args[1], regs, tmps)
        count_arg = instruction.args[1]
        count_bits = (
            count_arg.size * 8
            if isinstance(count_arg, IRValue) and type(count_arg.size) is int
            else None
        )
        if left is not None and right is not None:
            evaluated = _kb_binary_op_8616(
                instruction.op, left, right, count_bits,
                operands=(instruction.args[0], instruction.args[1]), result_size=dst.size,
            )
    elif instruction.op.startswith("Iop_") and len(instruction.args) == 1:
        arg = _kb_eval_value_8616(instruction.args[0], regs, tmps)
        if arg is not None:
            evaluated = _kb_unary_op_8616(instruction.op, arg)
    # An unevaluatable operand is bottom knowledge — ``(0, 0)`` — never a
    # missing tmp: dropping the row would also erase the partial knowledge
    # downstream rows could still derive (e.g. AND-with-constant zero
    # bits), and missing-vs-unknown changes ``tmps.get`` refusal behavior.
    tmps[dst.source_tmp] = (0, 0) if evaluated is None else evaluated


_SIGNED_ORDER_OPS_8616 = frozenset({"slt", "sle", "sgt", "sge"})
_UNSIGNED_ORDER_OPS_8616 = frozenset({"ult", "ule", "ugt", "uge"})


def _kb_eval_condition_8616(
    condition: IRCondition,
    regs: _KbRegs8616,
    tmps: _KbTmps8616,
) -> bool | None:
    """Evaluate one typed lifted condition against the abstract state.

    Three-valued over the known-bits lattice: ``zero``/``nonzero`` truth
    tests, boolean ``and``/``or``/``not`` composition, ``eq``/``ne``, the
    signed and unsigned ordering family, and ``masked_nonzero`` all reuse
    the exact bitvector rules above — the same IR semantics the census
    consumes, never a re-interpretation of machine bytes. Anything the
    lattice cannot prove returns ``None`` so the edge stays live.
    """
    args = condition.args
    # Two-operand masked forms keep their conjunctive semantics before
    # normalization maps ``masked_zero``/``masked_nonzero`` onto the
    # plain truth tests.
    if condition.op in ("masked_zero", "masked_nonzero") and len(args) == 2:
        return _kb_eval_masked_8616(condition, regs, tmps)
    op = normalize_condition_op_8616(condition.op)
    if op in ("nonzero", "zero") and len(args) == 1:
        return _kb_eval_truth_8616(op, args[0], regs, tmps)
    if op in ("and", "or") and len(args) == 2:
        return _kb_eval_junction_8616(op, args, regs, tmps)
    if op == "not" and len(args) == 1 and isinstance(args[0], IRCondition):
        inner = _kb_eval_condition_8616(args[0], regs, tmps)
        return None if inner is None else not inner
    if op in ("eq", "ne") and len(args) == 2:
        return _kb_eval_equality_8616(condition, op, regs, tmps)
    if op in _SIGNED_ORDER_OPS_8616 | _UNSIGNED_ORDER_OPS_8616 and len(args) == 2:
        return _kb_eval_order_8616(op, args, regs, tmps)
    return None


def _kb_eval_masked_8616(
    condition: IRCondition,
    regs: _KbRegs8616,
    tmps: _KbTmps8616,
) -> bool | None:
    """Conjunctive ``masked_zero``/``masked_nonzero`` truth."""
    args = condition.args
    if len(args) != 2:
        return None
    left_arg, right_arg = args
    if not isinstance(left_arg, IRValue) or not isinstance(right_arg, IRValue):
        return None
    left = _kb_eval_value_8616(left_arg, regs, tmps)
    right = _kb_eval_value_8616(right_arg, regs, tmps)
    width_mask = _kb_width_mask_8616(left_arg.size)
    if left is None or right is None or width_mask is None:
        return None
    conjunct = _kb_and_8616(left, right, width_mask)
    op: str = condition.op
    if conjunct[0] & conjunct[1]:
        return op == "masked_nonzero"
    if conjunct[0] == width_mask and conjunct[1] == 0:
        return op == "masked_zero"
    return None


def _kb_eval_truth_8616(
    op: str,
    atom: object,
    regs: _KbRegs8616,
    tmps: _KbTmps8616,
) -> bool | None:
    """``zero``/``nonzero`` truth over one typed value."""
    if not isinstance(atom, IRValue):
        return None
    kb = _kb_eval_value_8616(atom, regs, tmps)
    width_mask = _kb_width_mask_8616(atom.size)
    if kb is None or width_mask is None:
        return None
    if kb[0] & kb[1]:
        return op != "zero"
    if kb[0] == width_mask and kb[1] == 0:
        return op == "zero"
    return None


def _kb_eval_junction_8616(
    op: str,
    args: tuple[object, ...],
    regs: _KbRegs8616,
    tmps: _KbTmps8616,
) -> bool | None:
    """Boolean ``and``/``or`` composition over nested conditions."""
    sides = [
        _kb_eval_condition_8616(arg, regs, tmps)
        if isinstance(arg, IRCondition)
        else None
        for arg in args
    ]
    if op == "and":
        if False in sides:
            return False
        return True if sides == [True, True] else None
    if True in sides:
        return True
    return False if sides == [False, False] else None


def _kb_eval_equality_8616(
    condition: IRCondition,
    op: str,
    regs: _KbRegs8616,
    tmps: _KbTmps8616,
) -> bool | None:
    """``eq``/``ne`` at the comparison's authoritative width only."""
    args = condition.args
    if len(args) != 2:
        return None
    left_arg, right_arg = args
    if not isinstance(left_arg, IRValue) or not isinstance(right_arg, IRValue):
        return None
    left = _kb_eval_value_8616(left_arg, regs, tmps)
    right = _kb_eval_value_8616(right_arg, regs, tmps)
    if left is None or right is None:
        return None
    # Equality is only provable at the comparison's authoritative width —
    # the condition's own ``width_bits``, else the operands' declared byte
    # width when both agree. The union of *known* masks is never a width:
    # unknown high bits cannot establish equality.
    width_bits = condition.width_bits
    if type(width_bits) is int and 0 < width_bits <= 64:
        width_mask = (1 << width_bits) - 1
    else:
        left_mask = _kb_width_mask_8616(left_arg.size)
        right_mask = _kb_width_mask_8616(right_arg.size)
        if left_mask is None or right_mask is None or left_mask != right_mask:
            return None
        width_mask = left_mask
    # Narrow both operands to the comparison width — a 1-bit ``eq`` must
    # compare only bit 0 of a byte-wide stored const, not the whole mask.
    left = (left[0] & width_mask, left[1] & width_mask)
    right = (right[0] & width_mask, right[1] & width_mask)
    equal = _kb_cmp_eq_8616(left, right, width_mask)
    if equal[0] == 0:
        return None
    result = bool(equal[1])
    return result if op == "eq" else not result


def _kb_eval_order_8616(
    op: str,
    args: tuple[object, ...],
    regs: _KbRegs8616,
    tmps: _KbTmps8616,
) -> bool | None:
    """Signed/unsigned ordering needs both operands fully known."""
    if len(args) != 2:
        return None
    left_arg, right_arg = args
    if not isinstance(left_arg, IRValue) or not isinstance(right_arg, IRValue):
        return None
    left = _kb_eval_value_8616(left_arg, regs, tmps)
    right = _kb_eval_value_8616(right_arg, regs, tmps)
    left_mask = _kb_width_mask_8616(left_arg.size)
    right_mask = _kb_width_mask_8616(right_arg.size)
    if left is None or right is None:
        return None
    if left_mask is None or right_mask is None:
        return None
    if left[0] != left_mask or right[0] != right_mask:
        return None
    left_value, right_value = left[1], right[1]
    if op in _SIGNED_ORDER_OPS_8616:
        sign_l = 1 << (left_mask.bit_length() - 1)
        sign_r = 1 << (right_mask.bit_length() - 1)
        left_value = left[1] - ((left[1] & sign_l) << 1)
        right_value = right[1] - ((right[1] & sign_r) << 1)
    stem = op[1:]
    return {
        "lt": left_value < right_value,
        "le": left_value <= right_value,
        "gt": left_value > right_value,
        "ge": left_value >= right_value,
    }[stem]


def _cjmp_live_successor_8616(
    instruction: IRInstr,
    successors: Sequence[int],
    regs: _KbRegs8616,
    tmps: _KbTmps8616,
) -> int | None:
    """Return the single successor a CJMP row must take, when proven.

    The verdict comes only from the row's authoritative typed
    ``IRCondition`` — the same lifted predicate the importer produced —
    evaluated under the converged known-bits state at this row. When the
    condition proves true the exit target is the live edge; proven false,
    the other successor is. Anything unproven keeps both edges.
    """
    if len(instruction.args) != 2 or len(successors) != 2:
        return None
    condition, target = instruction.args
    if (
        not isinstance(condition, IRCondition)
        or not isinstance(target, IRValue)
        or type(target.const) is not int
    ):
        return None
    exit_target = target.const
    if exit_target not in successors:
        return None
    other = successors[0] if successors[1] == exit_target else successors[1]
    verdict = _kb_eval_condition_8616(condition, regs, tmps)
    if verdict is None:
        return None
    return exit_target if verdict else other


def _kb_call_row_8616(
    instruction: IRInstr,
    registers: _KbRegs8616,
    memory: PathMemory8616,
    apply_service: Callable[[IRInstr, dict[str, int], PathMemory8616], bool],
) -> _KbRegs8616:
    """Known-bits transfer for one CALL row.

    A declared interrupt-service boundary crosses through the caller's
    authenticated ``apply_service`` hook against the live path memory —
    the hook mutates ``memory`` with the service's own writes (frame,
    modeled metadata) before answering. Any other call taints the whole
    overlay and drops every register fact: an unbound callee may write
    memory anywhere, and the real census refuses the same row if the
    block stays live, so nothing is lost by keeping edges live here. A
    refused declared crossing also taints — the interrupt may have done
    anything.
    """
    declared = (
        instruction.dst is None
        and interrupt_call_vector_8616(instruction) is not None
    )
    if not declared:
        memory.taint()
        return {}
    known = _kb_known_registers_8616(registers)
    if apply_service(instruction, known, memory):
        return _kb_seed_state_8616(known)
    memory.taint()
    return {}


def _kb_transfer_effect_8616(
    instruction: IRInstr,
    registers: _KbRegs8616,
    memory: PathMemory8616,
    tmps: _KbTmps8616,
    dirty: set[str],
    instruction_entry: _KbRegs8616,
    apply_service: Callable[[IRInstr, dict[str, int], PathMemory8616], bool],
    read_load: Callable[[IRInstr, tuple[int, int] | None, PathMemory8616], int | None] | None = None,
) -> _KbRegs8616:
    """Transfer a store, call or data row using one instruction-entry snapshot."""
    if instruction.op == "STORE":
        _kb_store_row_8616(instruction, instruction_entry, dirty, tmps, memory)
        return registers
    if instruction.op == "CALL":
        result = _kb_call_row_8616(instruction, registers, memory, apply_service)
        tmps.clear()
        return result
    dst = instruction.dst
    if (
        instruction.op == "LOAD" and read_load is not None
        and isinstance(dst, IRValue) and dst.space is MemSpace.TMP
        and type(dst.source_tmp) is int
    ):
        value = read_load(instruction, _kb_store_span_8616(
            instruction, instruction.args[0] if instruction.args else None,
            instruction_entry, dirty, tmps,
        ), memory)
        mask = _kb_width_mask_8616(dst.size)
        if value is None or mask is None:
            tmps.pop(dst.source_tmp, None)
        else:
            tmps[dst.source_tmp] = (mask, value & mask)
        return registers
    _kb_data_row_8616(instruction, registers, tmps, dirty, instruction_entry)
    return registers


def _kb_repeat_exit_8616(
    block: IRBlock, registers: _KbRegs8616, memory: PathMemory8616,
    budget: list[int],
    apply_repeat: Callable[[IRBlock, dict[str, int], PathMemory8616, bool | None], RepeatedStoreStatus8616] | None,
) -> _KbPathState8616 | None:
    """Consume an authenticated repeat while preserving unrelated known bits."""
    if apply_repeat is None:
        return None
    known = _kb_known_registers_8616(registers)
    status = apply_repeat(block, known, memory, direction_fact_8616(registers))
    if status is RepeatedStoreStatus8616.NOT_APPLICABLE:
        return None
    budget[0] -= len(block.instrs) + 1
    if status is RepeatedStoreStatus8616.REFUSED or budget[0] < 0:
        return _KbPathState8616({}, path_memory_tainted_8616())
    for name in ("cx", "di"):
        value = known.get(name)
        _kb_write_register_8616(name, 2, None if value is None else (0xFFFF, value), registers)
    return _KbPathState8616(registers, memory)


def _kb_block_exit_8616(
    block: IRBlock,
    entry: _KbPathState8616,
    apply_service: Callable[[IRInstr, dict[str, int], PathMemory8616], bool],
    *,
    stop_after: int | None,
    sink: Callable[[IRInstr, _KbRegs8616, _KbTmps8616], None] | None,
    budget: list[int],
    read_load: Callable[[IRInstr, tuple[int, int] | None, PathMemory8616], int | None] | None = None,
    apply_repeat: Callable[[IRBlock, dict[str, int], PathMemory8616, bool | None], RepeatedStoreStatus8616] | None = None,
) -> _KbPathState8616:
    """Walk one block's rows in known-bits form; return the exit state.

    Tmp values persist across instruction rows exactly as the effect
    census models them (VEX tmps are block-local), and the
    instruction-entry snapshot plus dirty set mirror the census's
    machine-instruction discipline for store evaluation. STORE rows
    write the path memory overlay — proven spans and data become byte
    facts, unproven spans taint — so a declared-service crossing reads
    *current* memory, never stale initial bytes. CALL rows either cross
    a declared interrupt-service boundary through the caller-injected
    ``apply_service`` hook — the identical authenticated relation
    checks — or conservatively poison every fact and taint memory.
    Unclassified rows poison only their destination storage; control
    rows carry no register effect and CJMP rows additionally report to
    ``sink``.
    """
    registers = dict(entry.registers)
    memory = entry.memory.copy()
    repeated = _kb_repeat_exit_8616(block, registers, memory, budget, apply_repeat)
    if repeated is not None:
        return repeated
    tmps: _KbTmps8616 = {}
    instruction_entry = dict(registers)
    dirty: set[str] = set()
    current_addr: int | None = None
    for instruction in block.instrs:
        if type(instruction.addr) is not int:
            registers.clear()
            memory.taint()
            return _KbPathState8616(registers, memory)
        if stop_after is not None and instruction.addr > stop_after:
            break
        budget[0] -= 1
        if budget[0] < 0:
            registers.clear()
            memory.taint()
            return _KbPathState8616(registers, memory)
        if instruction.addr != current_addr:
            current_addr = instruction.addr
            instruction_entry = dict(registers)
            dirty = set()
        op = instruction.op
        if op == "CJMP":
            if _kb_cjmp_exit_8616(
                instruction, block, registers, tmps, sink
            ):
                return _KbPathState8616({}, path_memory_tainted_8616())
            break
        if op in ("JMP", "RET"):
            continue
        registers = _kb_transfer_effect_8616(
            instruction, registers, memory, tmps, dirty, instruction_entry, apply_service, read_load,
        )
    return _KbPathState8616(registers, memory)


def _kb_cjmp_exit_8616(
    instruction: IRInstr,
    block: IRBlock,
    registers: _KbRegs8616,
    tmps: _KbTmps8616,
    sink: Callable[[IRInstr, _KbRegs8616, _KbTmps8616], None] | None,
) -> bool:
    """Handle one conditional exit row; ``True`` means invalidate.

    A non-terminal CJMP cannot share one exit state between taken and
    fallthrough effects — the outgoing facts are invalidated rather than
    letting stale pre-exit state skip real writes. A terminal CJMP
    reports its snapshot to ``sink`` and ends the provable prefix: rows
    after it execute only on the not-taken path, and a second exit would
    need edge-local state this walker does not model.
    """
    if instruction is not block.instrs[-1]:
        return True
    if sink is not None:
        sink(instruction, dict(registers), dict(tmps))
    return False


def _kb_data_row_8616(
    instruction: IRInstr,
    registers: _KbRegs8616,
    tmps: _KbTmps8616,
    dirty: set[str],
    instruction_entry: _KbRegs8616,
) -> None:
    """Apply one non-control row's known-bits transfer.

    Closed register destinations receive the evaluated source (or drop
    their written bits when unproven) and dirty the written family so a
    later same-instruction store cannot read them through the entry
    snapshot; closed tmp destinations evaluate through the tmp lattice;
    register-less no-write rows are inert; any other shape
    conservatively poisons only its destination storage.
    """
    effect = scalar_instruction_effect_8616(instruction)
    dst = instruction.dst
    if (
        effect.kind is ScalarInstructionEffectKind8616.CLOSED_DESTINATION
        and effect.clobber is ScalarInstructionClobber8616.DATA_REGISTER
        and isinstance(dst, IRValue)
        and dst.space is MemSpace.REG
        and dst.name is not None
    ):
        evaluated = (
            _kb_eval_value_8616(instruction.args[0], registers, tmps)
            if instruction.op == "MOV" and len(instruction.args) == 1
            else None
        )
        _kb_write_register_8616(dst.name, dst.size, evaluated, registers)
        _kb_dirty_write_8616(dst.name, dirty)
        return
    if (
        effect.kind is ScalarInstructionEffectKind8616.CLOSED_DESTINATION
        and effect.clobber is ScalarInstructionClobber8616.NONE
        and isinstance(dst, IRValue)
        and dst.space is MemSpace.TMP
    ):
        _kb_tmp_write_8616(instruction, dst, registers, tmps)
        return
    if (
        effect.kind is ScalarInstructionEffectKind8616.NO_REGISTER_WRITE
        and effect.clobber is ScalarInstructionClobber8616.NONE
        and dst is None
    ):
        return
    _kb_poison_destination_8616(
        instruction, registers, tmps, dirty, instruction_entry
    )


def _kb_fixpoint_8616(
    blocks_by_addr: Mapping[int, IRBlock],
    dangerous: frozenset[int],
    predecessor_map: Mapping[int, Iterable[int]],
    head_addr: int,
    call_block_addr: int,
    callsite_addr: int,
    seed_state: _KbPathState8616,
    apply_service: Callable[[IRInstr, dict[str, int], PathMemory8616], bool],
    iteration_limit: int,
    deadline: float,
    budget: list[int],
    read_load: Callable[[IRInstr, tuple[int, int] | None, PathMemory8616], int | None] | None = None,
    apply_repeat: Callable[[IRBlock, dict[str, int], PathMemory8616, bool | None], RepeatedStoreStatus8616] | None = None,
    infeasible_edges: frozenset[tuple[int, int]] = frozenset(),
) -> dict[int, _KbPathState8616] | None:
    """Iterate the must-meet transfer to convergence, or ``None``.

    Mirrors ``_simulate_scope_8616``: the head meets the seed *and* its
    in-scope predecessor exits, non-head blocks wait for at least one
    predecessor exit, and iteration is bounded by the census's own limit.
    Register bits and memory bytes meet under the identical
    per-predecessor must discipline. Budget or deadline exhaustion
    returns ``None`` — no partial state. Only earlier fully proved dead
    edges may be excluded from predecessor meets during refinement.
    """
    entries: dict[int, _KbPathState8616] = {}
    exits: dict[int, _KbPathState8616] = {}
    for _ in range(iteration_limit):
        if time.monotonic() > deadline or budget[0] <= 0:
            return None
        changed = False
        for addr in sorted(dangerous):
            predecessors = [
                pred for pred in predecessor_map.get(addr, ())
                if pred in dangerous and (pred, addr) not in infeasible_edges
            ]
            if addr == head_addr:
                entry = _kb_meet_state_8616(
                    [
                        _KbPathState8616(
                            dict(seed_state.registers), seed_state.memory
                        )
                    ]
                    + [exits[pred] for pred in predecessors if pred in exits]
                )
            else:
                ready = [exits[pred] for pred in predecessors if pred in exits]
                if predecessors and not ready:
                    continue
                entry = _kb_meet_state_8616(ready)
            if entries.get(addr) == entry and addr in exits:
                continue
            entries[addr] = entry
            exits[addr] = _kb_block_exit_8616(
                blocks_by_addr[addr],
                entry,
                apply_service,
                stop_after=callsite_addr if addr == call_block_addr else None,
                sink=None,
                budget=budget,
                read_load=read_load,
                apply_repeat=apply_repeat,
            )
            changed = True
        if not changed:
            return entries
    return None


def _kb_cjmp_snapshots_8616(
    blocks_by_addr: Mapping[int, IRBlock],
    dangerous: frozenset[int],
    entries: Mapping[int, _KbPathState8616],
    call_block_addr: int,
    callsite_addr: int,
    apply_service: Callable[[IRInstr, dict[str, int], PathMemory8616], bool],
    deadline: float,
    budget: list[int],
    read_load: Callable[[IRInstr, tuple[int, int] | None, PathMemory8616], int | None] | None = None,
    apply_repeat: Callable[[IRBlock, dict[str, int], PathMemory8616, bool | None], RepeatedStoreStatus8616] | None = None,
) -> list[tuple[int, IRInstr, _KbRegs8616, _KbTmps8616]] | None:
    """Re-walk each converged block to capture terminal-CJMP states."""
    snapshots: list[tuple[int, IRInstr, _KbRegs8616, _KbTmps8616]] = []
    for addr in sorted(dangerous):
        if time.monotonic() > deadline or budget[0] <= 0:
            return None
        if addr not in entries:
            continue
        def collect_snapshot(
            instruction: IRInstr,
            regs: _KbRegs8616,
            tmps: _KbTmps8616,
            at: int = addr,
        ) -> None:
            """Retain a branch state with its current block's address."""
            snapshots.append((at, instruction, regs, tmps))

        _kb_block_exit_8616(
            blocks_by_addr[addr],
            entries[addr],
            apply_service,
            stop_after=callsite_addr if addr == call_block_addr else None,
            sink=collect_snapshot,
            budget=budget,
            read_load=read_load,
            apply_repeat=apply_repeat,
        )
    if time.monotonic() > deadline or budget[0] < 0:
        return None
    return snapshots


def _kb_infeasible_edges_8616(
    snapshots: Iterable[tuple[int, IRInstr, _KbRegs8616, _KbTmps8616]],
    blocks_by_addr: Mapping[int, IRBlock],
) -> list[tuple[int, int]]:
    """Publish per-edge verdicts only from terminal single-CJMP blocks.

    An earlier CJMP cannot decide edges a later exit may still take, and
    post-exit rows would need edge-local transfer state — those shapes
    keep every edge rather than publish a wrong verdict.
    """
    infeasible: list[tuple[int, int]] = []
    for block_addr, instruction, regs, tmps in snapshots:
        block = blocks_by_addr[block_addr]
        if (
            block.instrs[-1] is not instruction
            or sum(1 for row in block.instrs if row.op == "CJMP") != 1
        ):
            continue
        successors = sorted(block.successor_addrs)
        live = _cjmp_live_successor_8616(
            instruction, successors, regs, tmps
        )
        if live is None:
            continue
        for successor in successors:
            if successor != live:
                infeasible.append((block_addr, successor))
    return infeasible


def _kb_surviving_cone_8616(
    blocks_by_addr: Mapping[int, IRBlock],
    dangerous: frozenset[int],
    predecessor_map: Mapping[int, Iterable[int]],
    head_addr: int,
    call_block_addr: int,
    dead: frozenset[tuple[int, int]],
    deadline: float,
    budget: list[int],
) -> frozenset[int] | None:
    """Live scope = entry-reachable ∩ backward callsite cone, minus
    proven-dead edges. ``None`` on budget/deadline exhaustion."""
    reachable = {head_addr}
    pending = [head_addr]
    while pending:
        if time.monotonic() > deadline or budget[0] <= 0:
            return None
        addr = pending.pop()
        budget[0] -= 1
        for successor in blocks_by_addr[addr].successor_addrs:
            if (
                successor in dangerous
                and (addr, successor) not in dead
                and successor not in reachable
            ):
                reachable.add(successor)
                pending.append(successor)
    live_blocks = {call_block_addr}
    pending = [call_block_addr]
    while pending:
        if time.monotonic() > deadline or budget[0] <= 0:
            return None
        addr = pending.pop()
        budget[0] -= 1
        for predecessor in predecessor_map.get(addr, ()):
            if (
                predecessor in dangerous
                and (predecessor, addr) not in dead
                and predecessor not in live_blocks
            ):
                live_blocks.add(predecessor)
                pending.append(predecessor)
    live_blocks.intersection_update(reachable)
    if head_addr not in live_blocks:
        # The proven-dead edges imply the callsite itself is unreachable on
        # this invocation — a different semantic claim than an interior dead
        # branch. Publish the verdicts but keep the scope intact.
        return frozenset(dangerous)
    return frozenset(live_blocks)


def invocation_feasible_scope_8616(
    *,
    artifact: IRFunctionArtifact,
    dangerous: frozenset[int],
    predecessor_map: Mapping[int, Iterable[int]],
    head_addr: int,
    call_block_addr: int,
    callsite_addr: int,
    seed: Mapping[str, int],
    seed_memory: PathMemory8616,
    apply_service: Callable[[IRInstr, dict[str, int], PathMemory8616], bool],
    iteration_limit: int,
    deadline: float,
    work_limit: int,
    read_load: Callable[[IRInstr, tuple[int, int] | None, PathMemory8616], int | None] | None = None,
    apply_repeat: Callable[[IRBlock, dict[str, int], PathMemory8616, bool | None], RepeatedStoreStatus8616] | None = None,
) -> Real16EdgeFeasibility8616:
    """Prove which dangerous-cone edges are untraversable on this invocation.

    Forward must-meet known-bits interpretation over the exact in-scope
    blocks, seeded by the identical invocation state the effect census
    uses — registers start from ``seed`` and memory from ``seed_memory``
    (the unmodified initial image for a boot entry, the transported
    callsite overlay for a chained or enclosed entry), both meeting
    must-style per predecessor. The ``apply_service`` hook receives the
    projected fully-known register lanes *and* the live path memory so a
    declared service may only publish constants the current path bytes
    prove. Per-edge verdicts are read only from the converged fixpoint —
    provisional or budget-cut rounds publish no new pruning. Each completed
    round removes only proven-dead edges, then recomputes register and memory
    must-facts from the identical seed. All rounds share the original absolute
    deadline and work budget. On exhaustion, earlier committed evidence stays
    valid with ``converged=True`` for that retained dataflow round. This
    reports proof validity, not saturation of all refinements; no budget or
    deadline is reset.
    """
    blocks_by_addr = {block.addr: block for block in artifact.blocks}
    budget = [work_limit]

    live = frozenset(dangerous)
    dead: frozenset[tuple[int, int]] = frozenset()
    evaluated = 0

    def finish(converged: bool) -> Real16EdgeFeasibility8616:
        """Publish only fully committed rounds, including their consumed work."""
        return Real16EdgeFeasibility8616(
            live_blocks=live,
            infeasible_edges=tuple(sorted(dead)),
            evaluated_cjmps=evaluated,
            proven_edges=len(dead),
            converged=converged,
            work_units=work_limit - budget[0],
        )

    if any(addr not in blocks_by_addr for addr in dangerous):
        return finish(False)
    for _ in range(_EDGE_REFINEMENT_ROUND_LIMIT_8616):
        entries = _kb_fixpoint_8616(
            blocks_by_addr,
            live,
            predecessor_map,
            head_addr,
            call_block_addr,
            callsite_addr,
            _KbPathState8616(_kb_seed_state_8616(seed), seed_memory.copy()),
            apply_service,
            iteration_limit,
            deadline,
            budget,
            read_load,
            apply_repeat,
            infeasible_edges=dead,
        )
        if entries is None:
            return finish(bool(dead))
        snapshots = _kb_cjmp_snapshots_8616(
            blocks_by_addr,
            live,
            entries,
            call_block_addr,
            callsite_addr,
            apply_service,
            deadline,
            budget,
            read_load,
            apply_repeat,
        )
        if snapshots is None:
            return finish(bool(dead))
        candidate = dead | frozenset(_kb_infeasible_edges_8616(snapshots, blocks_by_addr))
        if candidate == dead:
            evaluated += len(snapshots)
            return finish(True)
        surviving = _kb_surviving_cone_8616(
            blocks_by_addr,
            dangerous,
            predecessor_map,
            head_addr,
            call_block_addr,
            candidate,
            deadline,
            budget,
        )
        if surviving is None:
            return finish(bool(dead))
        # Neither a provisional fixpoint nor a partial cone may publish
        # evidence. Commit the entire round, then restart from the same seed
        # under only the dead edges proved by these completed rounds.
        dead, live = candidate, surviving
        evaluated += len(snapshots)
    return finish(bool(dead))


def direction_fact_8616(registers: _KbRegs8616) -> bool | None:
    """Read DF only when its own bit is proven; other flags stay unknown."""
    flags = _kb_read_register_8616("flags", registers)
    if flags is None or not flags[0] & 0x400:
        return None
    return bool(flags[1] & 0x400)


class DirectionTracker8616:
    """Carry one DF fact using the existing typed known-bits row evaluator.

    Exact native binding remains the caller's responsibility. This is a
    projection of existing scalar semantics, not a second flags interpreter.
    Calls restart from their proven returned lanes; an untransported partial
    DF is conservatively lost. Joins belong to the enclosing path state.
    """

    def __init__(self, registers: Mapping[str, int], direction: bool | None) -> None:
        """Seed exact register lanes and, separately, the single known DF bit."""
        self.registers = _kb_seed_state_8616(registers)
        if direction is not None:
            self.registers["flags"] = (0x400, int(direction) << 10)
            self.registers["eflags"] = (0x400, int(direction) << 10)
        self.tmps: _KbTmps8616 = {}
        self.entry: _KbRegs8616 = dict(self.registers)
        self.dirty: set[str] = set()
        self.address: int | None = None

    def step(self, instruction: IRInstr, registers: Mapping[str, int], tmps: Mapping[int, int]) -> None:
        """Consume one already-authenticated row after its exact scalar transfer."""
        if instruction.addr != self.address:
            self.address = instruction.addr
            self.entry = dict(self.registers)
            self.dirty.clear()
        if instruction.op == "CALL":
            self.registers = _kb_seed_state_8616(registers)
            self.tmps.clear()
            return
        if instruction.op in ("STORE", "CJMP", "JMP", "RET"):
            return
        _kb_data_row_8616(instruction, self.registers, self.tmps, self.dirty, self.entry)
        dst = instruction.dst
        if instruction.op == "LOAD" and isinstance(dst, IRValue) and dst.source_tmp in tmps:
            assert dst.source_tmp is not None
            mask = _kb_width_mask_8616(dst.size)
            if mask is not None:
                self.tmps[dst.source_tmp] = (mask, tmps[dst.source_tmp] & mask)

    def direction(self) -> bool | None:
        """Return the proven DF bit, without asserting a complete FLAGS word."""
        return direction_fact_8616(self.registers)
