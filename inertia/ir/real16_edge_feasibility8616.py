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

import heapq
import re
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from inertia.semantics.register_value_preservation import (
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
from .frozen_dispatch import FrozenDispatch
from .frozen_dispatch import frozen_dispatch_lookup as frozen_dispatch_lookup
from .real16_declared_interrupt8616 import interrupt_call_vector_8616 as interrupt_call_vector_8616
from .real16_path_memory8616 import (
    SEGMENT_BASE_NAME_8616,
    SEGMENT_SHIFT_8616,
    PathMemory8616,
    meet_path_memory_8616,
)
from .real16_path_memory8616 import (
    path_memory_tainted_8616 as path_memory_tainted_8616,
)
from .real16_path_memory8616 import (
    store_atom_clean_8616 as store_atom_clean_8616,
)
from .real16_wide_multiply8616 import wide_multiply_shape_8616, wide_multiply_value_8616
from .scalar_instruction_effects import (
    ScalarInstructionClobber8616,
    ScalarInstructionEffectKind8616,
    scalar_instruction_effect_8616,
)
from .scalar_instruction_effects import (
    scalar_select_result_bits_8616 as scalar_select_result_bits_8616,
)

__all__ = [
    "EdgeFeasibilityProducerBindings8616",
    "Real16CallCutRequest8616",
    "Real16CallCutState8616",
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
class Real16CallCutRequest8616:
    """Select one exact terminal CALL; this request grants no authority."""

    artifact: IRFunctionArtifact
    block: IRBlock
    index: int
    instruction: IRInstr


@dataclass(frozen=True, slots=True)
class Real16CallCutState8616:
    """Detached pre-CALL snapshot data from the final committed current round.

    Identity references are not immutable source receipts. Consumers must
    authenticate current native sources and compare their own must-state.
    """

    artifact: IRFunctionArtifact
    block: IRBlock
    index: int
    instruction: IRInstr
    registers: tuple[tuple[str, int], ...]
    memory_known: tuple[tuple[int, int], ...]
    memory_unknown: tuple[int, ...]
    direction: bool | None


def _call_cut_owned_8616(
    request: Real16CallCutRequest8616, artifact: IRFunctionArtifact,
    dangerous: frozenset[int], head: int, budget: list[int], deadline: float,
    dead: frozenset[tuple[int, int]] = frozenset(),
) -> bool:
    """Charge exact row geometry and CFG reachability before optional capture."""
    budget[0] -= len(artifact.blocks) + len(request.block.instrs) + 1
    if budget[0] < 0 or time.monotonic() > deadline:
        return False
    block, index = request.block, request.index
    if request.artifact is not artifact or type(index) is not int or index < 0:
        return False
    if index != len(block.instrs) - 1 or block.instrs[index] is not request.instruction:
        return False
    if request.instruction.op != "CALL":
        return False
    if (sum(owned is block for owned in artifact.blocks) != 1
        or sum(owned.addr == block.addr for owned in artifact.blocks) != 1
        or any(row.op in ("RET", "JMP", "CJMP") for row in block.instrs[:index])):
        return False
    blocks = {owned.addr: owned for owned in artifact.blocks}
    ready, seen = [head], set()
    while ready:
        if budget[0] < 0 or time.monotonic() > deadline:
            return False
        addr = ready.pop()
        if addr in seen or addr not in dangerous or addr not in blocks:
            continue
        seen.add(addr)
        successors = blocks[addr].successor_addrs
        budget[0] -= len(successors) + 1
        ready.extend(successor for successor in successors if (addr, successor) not in dead)
    return budget[0] >= 0 and block.addr in seen


def _admit_call_cut_8616(
    request: Real16CallCutRequest8616 | None, artifact: IRFunctionArtifact,
    dangerous: frozenset[int], head: int, budget: list[int], deadline: float,
) -> Real16CallCutRequest8616 | None:
    """Normalize an optional exact selection without granting admission."""
    if request is None:
        return None
    return request if _call_cut_owned_8616(request, artifact, dangerous, head, budget, deadline) else None


def _capture_call_cut_8616(
    request: Real16CallCutRequest8616, registers: _KbRegs8616,
    memory: PathMemory8616, budget: list[int],
) -> Real16CallCutState8616 | None:
    """Prepay bounded projection and sorting; retain no mutable scalar alias."""
    lengths = (len(registers), len(memory.known), len(memory.unknown))
    budget[0] -= sum(n * (n.bit_length() + 2) for n in lengths) + 1
    if budget[0] < 0 or memory.tainted:
        return None
    return Real16CallCutState8616(
        request.artifact, request.block, request.index, request.instruction,
        tuple(sorted(_kb_known_registers_8616(registers).items())),
        tuple(sorted(memory.known.items())), tuple(sorted(memory.unknown)),
        direction_fact_8616(registers),
    )


def _current_call_cut_8616(
    cut: Real16CallCutState8616 | None, budget: list[int], deadline: float,
) -> Real16CallCutState8616 | None:
    """Drop optional data on expiry after all validation and result sorting."""
    if cut is None:
        return None
    return cut if budget[0] >= 0 and time.monotonic() <= deadline else None


def _observe_call_cut_8616(
    request: Real16CallCutRequest8616 | None, instruction: IRInstr,
    registers: _KbRegs8616, memory: PathMemory8616, budget: list[int],
    states: list[Real16CallCutState8616] | None,
) -> None:
    """Observe only the requested row without invoking any effect callback."""
    if request is None or instruction is not request.instruction or states is None:
        return
    captured = _capture_call_cut_8616(request, registers, memory, budget)
    if captured is not None:
        states.append(captured)


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
    call_cut: Real16CallCutState8616 | None = None


@dataclass(frozen=True, slots=True)
class Real16InvocationOrder8616:
    """One fresh CFG projection; no order on cycles or resource exhaustion."""

    blocks: tuple[int, ...] | None
    work_units: int

    @classmethod
    def from_walk(cls, order: list[int], scope: frozenset[int], work: int) -> Real16InvocationOrder8616:
        """Reject a cyclic partial walk without publishing a partial order."""
        return cls(tuple(order) if len(order) == len(scope) else None, work)


class LoadSnapshotReplay8616(Enum):
    """Whether a discarded LOAD transfer has an externally observable callback.

    READ_ONLY_OWNED is admitted only for owned readers with no mutation or
    external hooks. It never skips fixpoint LOADs or the native effect census.
    Unknown/dynamic readers retain OBSERVABLE replay by default.
    """

    OBSERVABLE = "observable"
    READ_ONLY_OWNED = "read_only_owned"


class BranchSnapshotReplay8616(Enum):
    """Whether branch observations need a second externally observable transfer.

    PURE_TRANSFER requires a side-effect-free service rejection and an owned
    read-only LOAD reader. CALL/repeat handlers and requested CALL-cut states
    retain ordinary replay. Observations never survive this dataflow request.
    """

    OBSERVABLE = "observable"
    PURE_TRANSFER = "pure_transfer"


def invocation_transfer_order_8616(
    scope: frozenset[int], proposed: tuple[int, ...] | None,
) -> tuple[int, ...] | None:
    """Keep sorted default traversal or require exact coverage without duplicates."""
    if proposed is None:
        return tuple(sorted(scope))
    if len(proposed) != len(scope) or frozenset(proposed) != scope:
        return None
    return proposed


def acyclic_invocation_order_8616(
    scope: frozenset[int], predecessors: Mapping[int, Iterable[int]], *,
    deadline: float, work_limit: int,
) -> Real16InvocationOrder8616:
    """Order an acyclic scope deterministically, charging node/edge visits.

    This is geometry, not an effect proof. Callers must preserve arbitrary
    callback schedules and use this projection only where their own transfers
    cannot mutate the CFG or external callback authority. A cycle retains the
    original bounded fixpoint; exhausted preparation grants no ordering.
    Strictly increasing in-scope edges establish the sorted order during
    collection, so that case needs no second node/edge walk through the heap.
    """
    degree = dict.fromkeys(scope, 0)
    successors: dict[int, list[int]] = {addr: [] for addr in scope}
    work = 0
    sorted_scope = sorted(scope)
    forward_only = True
    for addr in sorted_scope:
        work += 1
        if _invocation_order_budget_exhausted_8616(work, work_limit, deadline):
            return Real16InvocationOrder8616(None, work)
        for pred in predecessors.get(addr, ()):
            work += 1
            if _invocation_order_budget_exhausted_8616(work, work_limit, deadline):
                return Real16InvocationOrder8616(None, work)
            if pred in scope:
                degree[addr] += 1
                successors[pred].append(addr)
                forward_only = (forward_only and type(pred) is int
                                and type(addr) is int and pred < addr)
    if forward_only:
        return Real16InvocationOrder8616(tuple(sorted_scope), work)
    return _walk_acyclic_invocation_order_8616(
        scope, degree, successors, work, deadline=deadline, work_limit=work_limit,
    )


def _walk_acyclic_invocation_order_8616(
    scope: frozenset[int],
    degree: dict[int, int],
    successors: dict[int, list[int]],
    work: int,
    *,
    deadline: float,
    work_limit: int,
) -> Real16InvocationOrder8616:
    """Consume the fresh predecessor counts with a bounded deterministic Kahn walk."""
    pending = [addr for addr, count in degree.items() if count == 0]
    heapq.heapify(pending)
    order: list[int] = []
    while pending:
        work += 1
        if _invocation_order_budget_exhausted_8616(work, work_limit, deadline):
            return Real16InvocationOrder8616(None, work)
        addr = heapq.heappop(pending)
        order.append(addr)
        for successor in successors[addr]:
            work += 1
            if _invocation_order_budget_exhausted_8616(work, work_limit, deadline):
                return Real16InvocationOrder8616(None, work)
            degree[successor] -= 1
            if degree[successor] == 0:
                heapq.heappush(pending, successor)
    return Real16InvocationOrder8616.from_walk(order, scope, work)


def _invocation_order_budget_exhausted_8616(work: int, limit: int, deadline: float) -> bool:
    """Keep preparation inside its original charged-work and absolute-time bounds."""
    return work > limit or time.monotonic() > deadline


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


_KB_BINOP_PLAIN_8616: FrozenDispatch[str, Callable[[_Kb8616, _Kb8616, int], _Kb8616]] = (
    ("Add", _kb_add_8616),
    ("Sub", _kb_sub_8616),
    ("Mul", _kb_mul_8616),
    ("And", _kb_and_8616),
    ("Or", _kb_or_8616),
    ("Xor", _kb_xor_8616),
    ("CmpEQ", _kb_cmp_eq_8616),
    ("CmpNE", _kb_cmp_ne_8616),
)


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
    plain = frozen_dispatch_lookup(_KB_BINOP_PLAIN_8616, name)
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


def _kb_select_value_8616(
    instruction: IRInstr, regs: _KbRegs8616, tmps: _KbTmps8616,
) -> _Kb8616 | None:
    """Select one known arm, or retain only bits proven equal in both arms."""
    select_bits = scalar_select_result_bits_8616(instruction)
    if select_bits is None:
        return None
    evaluated: _Kb8616 | None = None
    guard = _kb_eval_value_8616(instruction.args[0], regs, tmps)
    result_mask = (1 << select_bits) - 1
    if guard is not None and guard[0] & 1:
        selected = _kb_eval_value_8616(
            instruction.args[1 if guard[1] & 1 else 2], regs, tmps,
        )
        if selected is not None:
            known = selected[0] & result_mask
            evaluated = (known, selected[1] & known)
    else:
        true_value = _kb_eval_value_8616(instruction.args[1], regs, tmps)
        false_value = _kb_eval_value_8616(instruction.args[2], regs, tmps)
        if true_value is not None and false_value is not None:
            # Without the guard, only bits known equal in both arms survive.
            known = (true_value[0] & false_value[0]
                     & ~(true_value[1] ^ false_value[1]) & result_mask)
            evaluated = (known, true_value[1] & known)
    return evaluated


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
    else:
        evaluated = _kb_select_value_8616(instruction, regs, tmps)
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


def _ordinary_call_target_8616(instruction: IRInstr) -> bool:
    """Admit typed native targets; the callback owns resolution and proof."""
    if instruction.op != "CALL" or instruction.dst is not None or len(instruction.args) != 1:
        return False
    target = instruction.args[0]
    if type(target) is not IRValue or target.size not in (2, 4):
        return False
    if target.space is MemSpace.CONST:
        return type(target.const) is int and 0 <= target.const < (1 << 20)
    if target.space is MemSpace.TMP:
        # Native near-call coordinates may be dword expressions after segment
        # and offset composition. Their shape grants no target authority.
        return True
    return target.space is MemSpace.REG and type(target.name) is str and bool(target.name)


def _kb_call_row_8616(
    instruction: IRInstr,
    registers: _KbRegs8616,
    memory: PathMemory8616,
    apply_service: Callable[[IRInstr, dict[str, int], PathMemory8616], bool],
    apply_call: Callable[[IRInstr, dict[str, int], PathMemory8616], bool] | None = None,
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
    anything. The optional ordinary ``apply_call`` hook is a caller-owned
    authentication boundary: only exact True consumes its fully known register
    projection and live memory effects; absent/refused/malformed calls taint.
    """
    declared = (
        instruction.dst is None
        and interrupt_call_vector_8616(instruction) is not None
    )
    known = _kb_known_registers_8616(registers)
    if declared:
        if apply_service(instruction, known, memory):
            return _kb_seed_state_8616(known)
    elif (apply_call is not None and _ordinary_call_target_8616(instruction)
          and apply_call(instruction, known, memory) is True):
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
    apply_call: Callable[[IRInstr, dict[str, int], PathMemory8616], bool] | None = None,
) -> _KbRegs8616:
    """Transfer a store, call or data row using one instruction-entry snapshot."""
    if instruction.op == "STORE":
        _kb_store_row_8616(instruction, instruction_entry, dirty, tmps, memory)
        return registers
    if instruction.op == "CALL":
        result = _kb_call_row_8616(instruction, registers, memory, apply_service, apply_call)
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
    apply_call: Callable[[IRInstr, dict[str, int], PathMemory8616], bool] | None = None,
    call_cut: Real16CallCutRequest8616 | None = None,
    cut_states: list[Real16CallCutState8616] | None = None,
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
        if call_cut is not None:
            _observe_call_cut_8616(call_cut, instruction, registers, memory, budget, cut_states)
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
            return _kb_cjmp_path_exit_8616(instruction, block, registers, tmps, memory, sink)
        if op in ("JMP", "RET"):
            continue
        registers = _kb_transfer_effect_8616(
            instruction, registers, memory, tmps, dirty, instruction_entry, apply_service, read_load, apply_call,
        )
    return _KbPathState8616(registers, memory)


def _kb_cjmp_path_exit_8616(
    instruction: IRInstr, block: IRBlock, registers: _KbRegs8616,
    tmps: _KbTmps8616, memory: PathMemory8616,
    sink: Callable[[IRInstr, _KbRegs8616, _KbTmps8616], None] | None,
) -> _KbPathState8616:
    """Close the branch walk with the existing terminal-row validity check."""
    if _kb_cjmp_exit_8616(instruction, block, registers, tmps, sink):
        return _KbPathState8616({}, path_memory_tainted_8616())
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
    if type(sink) is _BranchTransferCollector8616:
        # This owned sink consumes the values immediately and retains only
        # integer CFG edges. External sinks still receive detached maps.
        sink(instruction, registers, tmps)
    elif sink is not None:
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


@dataclass(frozen=True, slots=True)
class _BranchTransferObservation8616:
    """Provisional edge verdict from one block's latest entry state."""

    infeasible_edges: tuple[tuple[int, int], ...]
    evaluated_cjmps: int


@dataclass(slots=True)
class _BranchTransferCollector8616:
    """Consume a terminal branch immediately without retaining machine-state maps."""

    block: IRBlock
    observations: dict[int, _BranchTransferObservation8616]
    budget: list[int]

    def __call__(self, instruction: IRInstr, registers: _KbRegs8616, tmps: _KbTmps8616) -> None:
        """Record only the first, terminal branch admitted by the normal walker."""
        successors = sorted(self.block.successor_addrs)
        self.budget[0] -= len(successors) + 1
        live = _cjmp_live_successor_8616(instruction, successors, registers, tmps)
        edges = tuple((self.block.addr, successor) for successor in successors
                      if live is not None and successor != live)
        self.observations[self.block.addr] = _BranchTransferObservation8616(edges, 1)


def _branch_transfer_collector_8616(
    observations: dict[int, _BranchTransferObservation8616] | None,
    block: IRBlock, budget: list[int],
) -> _BranchTransferCollector8616 | None:
    """Replace provisional observations whenever the block entry changes."""
    if observations is None:
        return None
    observations[block.addr] = _BranchTransferObservation8616((), 0)
    return _BranchTransferCollector8616(block, observations, budget)


def _kb_entry_chain_edges_8616(
    blocks: Mapping[int, IRBlock], scope: frozenset[int],
    predecessors: Mapping[int, Iterable[int]], head: int, terminal: int,
    stop: int, seed: _KbPathState8616,
    apply_service: Callable[[IRInstr, dict[str, int], PathMemory8616], bool],
    read_load: Callable[[IRInstr, tuple[int, int] | None, PathMemory8616], int | None] | None,
    deadline: float, budget: list[int],
) -> frozenset[tuple[int, int]] | None:
    """Evaluate an entry chain with no joins or backedges under pure effects.

    The entry must have no in-scope predecessors. Every subsequent block must
    have exactly the previous block as its sole predecessor, and the preceding
    transfer must prove exactly one live successor. Thus each input is final
    without a loop fixpoint. Only edge candidates escape; the caller still
    requires its complete converged transfer before publishing observations.
    """
    addr, previous, state = head, None, seed
    visited: set[int] = set()
    dead: set[tuple[int, int]] = set()
    while addr in scope and addr not in visited:
        incoming = tuple(predecessors.get(addr, ()))
        budget[0] -= len(incoming) + 1
        if budget[0] <= 0 or time.monotonic() > deadline:
            return None
        required: set[int] = set() if previous is None else {previous}
        if {pred for pred in incoming if pred in scope} != required:
            break
        visited.add(addr)
        block = blocks[addr]
        observations: dict[int, _BranchTransferObservation8616] = {}
        state = _kb_block_exit_8616(
            block, state, apply_service,
            stop_after=stop if addr == terminal else None,
            sink=_branch_transfer_collector_8616(observations, block, budget),
            budget=budget, read_load=read_load,
        )
        if budget[0] < 0 or time.monotonic() > deadline:
            return None
        dead.update(observations[addr].infeasible_edges)
        successors = tuple(target for target in block.successor_addrs
                           if (addr, target) not in dead)
        budget[0] -= len(block.successor_addrs)
        if addr == terminal or len(successors) != 1:
            break
        previous, addr = addr, successors[0]
    return frozenset(dead)


def _kb_entry_chain_scope_8616(
    blocks: Mapping[int, IRBlock], scope: frozenset[int],
    predecessors: Mapping[int, Iterable[int]], head: int, terminal: int,
    stop: int, seed: _KbPathState8616,
    apply_service: Callable[[IRInstr, dict[str, int], PathMemory8616], bool],
    read_load: Callable[[IRInstr, tuple[int, int] | None, PathMemory8616], int | None] | None,
    deadline: float, budget: list[int], dead: frozenset[tuple[int, int]],
    *, enabled: bool,
) -> tuple[frozenset[int], frozenset[tuple[int, int]]] | None:
    """Restrict the first pure transfer by independently final entry guards.

    Three-block and smaller callees retain the single transfer to avoid
    adding a cone walk to the common short leaf path.
    Refined rounds already exclude the guard edges and need no extra replay.
    """
    if not enabled or dead or len(scope) <= 3:
        return scope, dead
    entry_dead = _kb_entry_chain_edges_8616(
        blocks, scope, predecessors, head, terminal, stop, seed,
        apply_service, read_load, deadline, budget,
    )
    if entry_dead is None:
        return None
    if not entry_dead:
        return scope, dead
    surviving = _kb_surviving_cone_8616(
        blocks, scope, predecessors, head, terminal, entry_dead, deadline, budget,
    )
    return None if surviving is None else (surviving, entry_dead)


def _kb_ready_entry_8616(
    predecessors: Sequence[int], exits: Mapping[int, _KbPathState8616],
    seed: _KbPathState8616 | None,
) -> _KbPathState8616 | None:
    """Meet ready predecessors and an optional entry seed; defer pending nodes."""
    ready = [exits[pred] for pred in predecessors if pred in exits]
    if seed is not None:
        ready.insert(0, _KbPathState8616(dict(seed.registers), seed.memory))
    elif predecessors and not ready:
        return None
    return _kb_meet_state_8616(ready)


@dataclass(frozen=True, slots=True)
class _KbFixpointResult8616:
    """Completed local round and the exact CFG inputs used for its transfers.

    Entry-chain pruning can narrow those inputs before iteration. Keeping
    that fact prevents an identical completed round from being rerun merely
    because the outer refinement owner still remembers the larger input.
    No record escapes an incomplete round or survives this feasibility call.
    """

    entries: dict[int, _KbPathState8616]
    live_blocks: frozenset[int]
    infeasible_edges: frozenset[tuple[int, int]]


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
    apply_call: Callable[[IRInstr, dict[str, int], PathMemory8616], bool] | None = None,
    transfer_order: tuple[int, ...] | None = None,
    branch_snapshots: dict[int, _BranchTransferObservation8616] | None = None,
) -> _KbFixpointResult8616 | None:
    """Iterate the must-meet transfer to convergence, or ``None``.

    Mirrors ``_simulate_scope_8616``: the head meets the seed *and* its
    in-scope predecessor exits, non-head blocks wait for at least one
    predecessor exit, and iteration is bounded by the census's own limit.
    Register bits and memory bytes meet under the identical
    per-predecessor must discipline. Budget or deadline exhaustion
    returns ``None`` — no partial state. Only earlier fully proved dead
    edges may be excluded from predecessor meets during refinement.
    """
    order = invocation_transfer_order_8616(dangerous, transfer_order)
    if order is None:
        return None
    if branch_snapshots is not None:
        initial = _kb_entry_chain_scope_8616(
            blocks_by_addr, dangerous, predecessor_map, head_addr,
            call_block_addr, callsite_addr, seed_state, apply_service,
            read_load, deadline, budget, infeasible_edges,
            enabled=iteration_limit > 1,
        )
        if initial is None:
            return None
        dangerous, infeasible_edges = initial
        order = tuple(addr for addr in order if addr in dangerous)
    entries: dict[int, _KbPathState8616] = {}
    exits: dict[int, _KbPathState8616] = {}
    for _ in range(iteration_limit):
        if time.monotonic() > deadline or budget[0] <= 0:
            return None
        changed = False
        for addr in order:
            predecessors = [
                pred for pred in predecessor_map.get(addr, ())
                if pred in dangerous and (pred, addr) not in infeasible_edges
            ]
            entry = _kb_ready_entry_8616(
                predecessors, exits, seed_state if addr == head_addr else None,
            )
            if entry is None:
                continue
            if entries.get(addr) == entry and addr in exits:
                continue
            entries[addr] = entry
            exits[addr] = _kb_block_exit_8616(
                blocks_by_addr[addr],
                entry,
                apply_service,
                stop_after=callsite_addr if addr == call_block_addr else None,
                sink=_branch_transfer_collector_8616(branch_snapshots, blocks_by_addr[addr], budget),
                budget=budget,
                read_load=read_load,
                apply_repeat=apply_repeat,
                apply_call=apply_call,
            )
            changed = True
        if not changed:
            return _KbFixpointResult8616(entries, dangerous, infeasible_edges)
    return None


def _kb_snapshot_observed_8616(
    block: IRBlock, *, has_load_hook: bool,
    exempt_call: IRInstr | None = None,
    call_replay_unobserved: Callable[[IRInstr], bool] | None = None,
) -> bool:
    """Keep branch/hook replay; pure owned transfers have no snapshot observer.

    This classification is fresh at consumption, never retained across hooks.
    A scalar/store transfer only changes the copied block-local exit state,
    which the snapshot pass discards. Its actual effects remain in the fixpoint
    and the subsequent native census. Unknown effects and non-owned block,
    instruction or operation types retain the walker. Repeat hooks precede it
    because even NOT_APPLICABLE may change external authentication state.
    ``exempt_call`` is a single instruction object the caller proved inert:
    only that exact row object skips the CALL observability check.
    ``call_replay_unobserved`` is a per-row, per-moment verdict that consulting the
    call handler on one exact row is confined to the discarded walk state —
    the mandatory fixpoint transfer already ran the identical consult, so a
    second consultation cannot publish a new retained effect. A declined or
    absent verdict keeps every CALL row, and thus the block, observed.
    """
    if type(block) is not IRBlock:
        return True
    for instruction in block.instrs:
        if type(instruction) is not IRInstr or type(instruction.op) is not str:
            return True
        if instruction.op in ("CJMP", "CALL") or (
            instruction.op == "LOAD" and has_load_hook
        ):
            if instruction.op == "CALL" and (
                instruction is exempt_call
                or (call_replay_unobserved is not None and call_replay_unobserved(instruction))
            ):
                continue
            return True
        if instruction.op == "RET":
            continue
        if scalar_instruction_effect_8616(instruction).kind is ScalarInstructionEffectKind8616.UNKNOWN:
            return True
    return False


def _snapshot_terminal_exemption_8616(
    block: IRBlock, call_block_addr: int, callsite_addr: int,
    terminal_call_noop: Callable[[IRInstr], bool] | None,
    call_cut: Real16CallCutRequest8616 | None,
) -> IRInstr | None:
    """Select one inert last CALL without losing a requested pre-CALL cut."""
    if (terminal_call_noop is None or block.addr != call_block_addr
            or type(block.instrs) is not tuple or not block.instrs):
        return None
    instruction = block.instrs[-1]
    if (type(instruction) is not IRInstr or instruction.op != "CALL"
            or instruction.addr != callsite_addr):
        return None
    if call_cut is not None and call_cut.block is block:
        return None
    return instruction if terminal_call_noop(instruction) else None


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
    apply_call: Callable[[IRInstr, dict[str, int], PathMemory8616], bool] | None = None,
    load_snapshot_replay: LoadSnapshotReplay8616 = LoadSnapshotReplay8616.OBSERVABLE,
    repeat_consult_noop: Callable[[IRBlock], bool] | None = None,
    load_reader_readonly: Callable[[], bool] | None = None,
    terminal_call_noop: Callable[[IRInstr], bool] | None = None,
    call_replay_unobserved: Callable[[IRInstr], bool] | None = None,
    call_cut: Real16CallCutRequest8616 | None = None,
    cut_states: list[Real16CallCutState8616] | None = None,
) -> list[tuple[int, IRInstr, _KbRegs8616, _KbTmps8616]] | None:
    """Freshly replay branch/hook blocks, discarding unobserved pure exits.

    Charge one selection unit per classified block. Full row transfer charges
    remain for every replayed block; omitted transfers publish no state.
    With ``apply_repeat`` present, an optional ``repeat_consult_noop``
    predicate may prove per block that the repeat consultation is a
    side-effect-free non-candidate at the current moment; only then does the
    walk pay one selection unit for the guard/classification stage, whether
    the block is then omitted or replayed. ``load_reader_readonly`` is the
    per-moment ownedness verdict for the LOAD reader; absent or ``False``
    keeps hooked LOAD rows observable. ``terminal_call_noop`` is the
    per-moment verdict that consulting the call handler on one exact row is
    inert; it can exempt only the last row of the selected stopping block at
    the stopping coordinate, never under a requested cut for that block.
    ``call_replay_unobserved`` is the per-moment verdict that consulting the call
    handler on one exact row is confined to the discarded walk state —
    the fixpoint already ran the identical consult on the identical
    converged entry, so only its discarded dataflow output repeats here.
    It is withheld entirely on a block carrying a requested cut, whose
    detached pre-CALL capture remains an obligatory replay product. A
    ``False`` verdict or a missing predicate retains the unconditional
    replay, including the repeat and call consultations.
    """
    snapshots: list[tuple[int, IRInstr, _KbRegs8616, _KbTmps8616]] = []
    for addr in sorted(dangerous):
        if time.monotonic() > deadline or budget[0] <= 0:
            return None
        if addr not in entries:
            continue
        block = blocks_by_addr[addr]
        cut_block = call_cut is not None and call_cut.block is block
        if apply_repeat is None:
            budget[0] -= 1
            if not _kb_snapshot_observed_8616(
                block, has_load_hook=(
                    read_load is not None
                    and load_snapshot_replay is not LoadSnapshotReplay8616.READ_ONLY_OWNED
                ),
                call_replay_unobserved=None if cut_block else call_replay_unobserved,
            ):
                continue
        elif repeat_consult_noop is not None and repeat_consult_noop(block):
            budget[0] -= 1
            exempt_call = _snapshot_terminal_exemption_8616(
                block, call_block_addr, callsite_addr, terminal_call_noop, call_cut,
            )
            if not _kb_snapshot_observed_8616(
                block, has_load_hook=(
                    read_load is not None
                    and not (load_reader_readonly is not None and load_reader_readonly())
                ), exempt_call=exempt_call,
                call_replay_unobserved=None if cut_block else call_replay_unobserved,
            ):
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
            apply_call=apply_call,
            call_cut=call_cut if cut_block else None,
            cut_states=cut_states,
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


def _kb_refinement_inputs_changed_8616(
    previous_live: frozenset[int],
    surviving: frozenset[int],
    new_dead: frozenset[tuple[int, int]],
    deadline: float,
    budget: list[int],
) -> bool | None:
    """Require another transfer only for changed cone blocks or internal edges.

    Predecessor meets consume edges with both endpoints in the live cone.
    Removing an external edge while keeping the same cone changes no transfer
    predecessor-meet input. This detects convergence after a complete round; it neither
    reuses a proof nor omits a hook from a requested transfer. None means the
    bounded selection did not finish, so only the committed round may survive.
    """
    if time.monotonic() > deadline or budget[0] <= 0:
        return None
    budget[0] -= 1
    if surviving != previous_live:
        return True
    for source, target in new_dead:
        budget[0] -= 1
        if budget[0] < 0 or time.monotonic() > deadline:
            return None
        if source in previous_live and target in previous_live:
            return True
    return False


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
    apply_call: Callable[[IRInstr, dict[str, int], PathMemory8616], bool] | None = None,
    transfer_order: tuple[int, ...] | None = None,
    load_snapshot_replay: LoadSnapshotReplay8616 = LoadSnapshotReplay8616.OBSERVABLE,
    repeat_consult_noop: Callable[[IRBlock], bool] | None = None,
    load_reader_readonly: Callable[[], bool] | None = None,
    terminal_call_noop: Callable[[IRInstr], bool] | None = None,
    call_replay_unobserved: Callable[[IRInstr], bool] | None = None,
    call_cut: Real16CallCutRequest8616 | None = None,
    branch_snapshot_replay: BranchSnapshotReplay8616 = BranchSnapshotReplay8616.OBSERVABLE,
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
    prove. Optional ``apply_call`` consumes authenticated ordinary callee effects
    under the same fully-known projection; unknown calls still taint and keep
    edges live. This callback grants no independent callee authority. Per-edge verdicts are read only from the converged fixpoint —
    provisional or budget-cut rounds publish no new pruning. Each completed
    round removes only proven-dead edges, then recomputes register and memory
    must-facts from the identical seed. All rounds share the original absolute
    deadline and work budget. On exhaustion, earlier committed evidence stays
    valid with ``converged=True`` for that retained dataflow round. This
    reports proof validity, not saturation of all refinements; no budget or
    deadline is reset. An optional order is a freshly prepared CFG projection
    admitted by a consumer with read-only callbacks; ordinary callers retain
    their existing sorted schedule. It never authorizes cached effects.
    A read-only owned LOAD reader may omit discarded branchless snapshot
    transfers; generic readers retain callback replay. Branch states and the
    complete fixpoint/census remain mandatory with either policy.
    A newly dead edge outside an unchanged live cone alters no predecessor
    meet; the completed round already establishes dataflow convergence there.
    Internal-edge removal still recomputes facts even if all blocks survive.
    An optional exact ``call_cut`` retains detached pre-CALL data during the
    existing snapshot walk, charging copies and selection to this budget.
    Only a complete final round with unchanged refinement inputs publishes
    it; retained earlier pruning never authorizes a provisional cut state.
    This data is neither source authentication nor prefix reuse admission.
    ``PURE_TRANSFER`` additionally permits the owning callee walker to collect
    branch verdicts during each transfer. That policy requires a no-op service
    handler and read-only LOADs; CALL/repeat handlers and cut requests retain
    fresh replay. Provisional verdicts are replaced on changed block entries
    and discarded unless the entire round converges within the original budget.
    ``call_replay_unobserved`` is the caller-owned per-moment verdict that a CALL row's
    replay consult is confined to discarded state — the mandatory fixpoint
    already consulted the identical handler on the identical converged entry.
    Only blocks whose every CALL row earns that verdict lose their replay;
    interrupt/service rows, foreign consult chains and cut-carrying blocks
    always retain it.
    """
    blocks_by_addr = {block.addr: block for block in artifact.blocks}
    budget = [work_limit]

    live = frozenset(dangerous)
    dead: frozenset[tuple[int, int]] = frozenset()
    evaluated = 0
    call_cut = _admit_call_cut_8616(call_cut, artifact, dangerous, head_addr, budget, deadline)

    def finish(converged: bool, cut: Real16CallCutState8616 | None = None) -> Real16EdgeFeasibility8616:
        """Publish only fully committed rounds, including their consumed work."""
        if cut is not None and call_cut is not None and not _call_cut_owned_8616(
            call_cut, artifact, live, head_addr, budget, deadline, dead,
        ):
            cut = None
        ordered_dead = tuple(sorted(dead))
        cut = _current_call_cut_8616(cut, budget, deadline)
        return Real16EdgeFeasibility8616(
            live_blocks=live,
            infeasible_edges=ordered_dead,
            evaluated_cjmps=evaluated,
            proven_edges=len(dead),
            converged=converged,
            work_units=work_limit - budget[0],
            call_cut=cut,
        )

    requested_order = invocation_transfer_order_8616(dangerous, transfer_order)
    if requested_order is None or any(addr not in blocks_by_addr for addr in dangerous):
        return finish(False)
    for _ in range(_EDGE_REFINEMENT_ROUND_LIMIT_8616):
        branch_snapshots: dict[int, _BranchTransferObservation8616] | None = (
            {} if branch_snapshot_replay is BranchSnapshotReplay8616.PURE_TRANSFER
            and apply_call is None and apply_repeat is None and call_cut is None
            and (read_load is None or load_snapshot_replay is LoadSnapshotReplay8616.READ_ONLY_OWNED)
            else None
        )
        completed = _kb_fixpoint_8616(
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
            apply_call=apply_call,
            transfer_order=tuple(addr for addr in requested_order if addr in live),
            branch_snapshots=branch_snapshots,
        )
        if completed is None:
            return finish(bool(dead))
        cut_states: list[Real16CallCutState8616] = []
        snapshots = (
            []
            if branch_snapshots is not None else _kb_cjmp_snapshots_8616(
                blocks_by_addr,
                live,
                completed.entries,
                call_block_addr,
                callsite_addr,
                apply_service,
                deadline,
                budget,
                read_load,
                apply_repeat,
                apply_call,
                load_snapshot_replay=load_snapshot_replay,
                repeat_consult_noop=repeat_consult_noop,
                load_reader_readonly=load_reader_readonly,
                terminal_call_noop=terminal_call_noop,
                call_replay_unobserved=call_replay_unobserved,
                call_cut=call_cut, cut_states=cut_states,
            )
        )
        if snapshots is None or time.monotonic() > deadline or budget[0] < 0:
            return finish(bool(dead))
        observed_dead = (
            frozenset(edge for observation in branch_snapshots.values() for edge in observation.infeasible_edges)
            if branch_snapshots is not None else frozenset(_kb_infeasible_edges_8616(snapshots, blocks_by_addr))
        )
        candidate = dead | observed_dead
        observations = (sum(row.evaluated_cjmps for row in branch_snapshots.values())
                        if branch_snapshots is not None else len(snapshots))
        if candidate == dead:
            evaluated += observations
            return finish(True, cut_states[0] if len(cut_states) == 1 else None)
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
        inputs_changed = _kb_refinement_inputs_changed_8616(
            completed.live_blocks, surviving,
            candidate - completed.infeasible_edges, deadline, budget,
        )
        dead, live = candidate, surviving
        evaluated += observations
        if inputs_changed is not True:
            return finish(True, cut_states[0] if inputs_changed is False and len(cut_states) == 1 else None)
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


class EdgeFeasibilityProducerBindings8616(Protocol):
    """Typed namespace of helper identities actually retained by this consumer.

    This metadata view grants no call authority and invokes no accessor.
    Consumers read the existing module bindings directly for cache keys.
    """

    scalar_instruction_effect_8616: object
    register_value_family_8616: object
    register_value_projection_8616: object
    wide_multiply_shape_8616: object
    wide_multiply_value_8616: object
