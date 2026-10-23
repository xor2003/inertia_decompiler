"""Layer: tests.

Responsibility: bound the per-comparison cost of the native binding
comparator on shared immutable IR DAGs and pin the exact refusal
semantics a memoized comparator must preserve — depth exhaustion,
shallow-proven pairs re-queried past the depth bound, unknown
self-identical dataclasses, mutable sequence nodes, and field-level
divergence including ``compare=False`` capture ids.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

import pytest

import inertia.ir.real16_invocation_domain as dom
from inertia.ir.core import (
    IRBinaryValue,
    IRBlock,
    IRInstr,
    IRValue,
    MemSpace,
)


@dataclass(frozen=True)
class _OpaqueTerm:
    """A dataclass the native binding comparator does not own."""

    payload: int


class _IntLikeMeta(type):
    """An opaque type whose equality misleadingly advertises a builtin kind."""

    def __eq__(cls, other: object) -> bool:
        return other is int

    def __hash__(cls) -> int:
        return type.__hash__(cls)


@dataclass(frozen=True)
class _OpaqueIntLikeTerm(metaclass=_IntLikeMeta):
    """An unowned node must refuse regardless of its metaclass equality."""

    payload: int


def _const(value: int) -> IRValue:
    """Build one typed constant leaf."""
    return IRValue(MemSpace.CONST, const=value, size=2)


def _shared_dag_pair(rows: int) -> tuple[IRBlock, IRBlock]:
    """Two equal blocks whose every row re-shares one operand sub-DAG."""

    def block() -> IRBlock:
        leaf = _const(7)
        index = IRBinaryValue("Iop_Add16", leaf, _const(3), size=2)
        shared = IRValue(MemSpace.REG, name="bx", size=2, index=index)
        return IRBlock(
            addr=0x1000,
            instrs=tuple(
                IRInstr(
                    "MOV",
                    IRValue(MemSpace.REG, name="ax", size=2),
                    (shared,),
                    size=2,
                    addr=0x1000 + row,
                )
                for row in range(rows)
            ),
            refusals=(),
            successor_addrs=(0x2000,),
        )

    return block(), block()


def test_shared_dag_operand_is_evaluated_once_per_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One shared operand pair must cost one subtree evaluation, not rows.

    Without the per-comparison memo the comparator re-walks the shared
    immutable operand sub-DAG once per row; with it the identical pair
    resolves from the memo. A second top-level comparison re-evaluates —
    the memo is per-comparison, never a cross-request proof cache.
    """
    left, right = _shared_dag_pair(rows=64)
    shared_pair = (id(left.instrs[0].args[0]), id(right.instrs[0].args[0]))
    evaluations = 0
    real_value_comparator = dom.frozen_dispatch_lookup(dom._NATIVE_COMPARATORS_8616, IRValue)
    assert real_value_comparator is not None

    def counting(left_term: object, right_term: object, depth: int, *rest: object) -> bool:
        nonlocal evaluations
        if (id(left_term), id(right_term)) == shared_pair:
            evaluations += 1
        return real_value_comparator(left_term, right_term, depth, *rest)

    monkeypatch.setattr(dom, "_NATIVE_COMPARATORS_8616", {**dict(dom._NATIVE_COMPARATORS_8616), IRValue: counting})
    assert dom._native_block_bound_8616(left, right) is True
    assert evaluations == 1
    assert dom._native_block_bound_8616(left, right) is True
    assert evaluations == 2


def test_shallow_proven_pair_cannot_bypass_deeper_depth_query() -> None:
    """A memoized ``True`` is valid only at depths up to where it was proven.

    The same ``(left, right)`` object pair appears first at a shallow
    depth where its nested subtree fits the bound, then nested deeper
    where the identical subtree must exceed it. The memo hit at the
    deeper query must refuse rather than reuse the shallow ``True``;
    the whole block binds ``False`` exactly as the unmemoized comparator.
    """
    leaf = _const(1)
    shared_subtree: IRBinaryValue = IRBinaryValue("Iop_Add16", leaf, leaf, size=2)
    for _ in range(3):
        shared_subtree = IRBinaryValue(
            "Iop_Add16", leaf, shared_subtree, size=2
        )
    left_shared = IRValue(
        MemSpace.REG, name="bx", size=2, index=shared_subtree
    )
    right_shared = IRValue(
        MemSpace.REG, name="bx", size=2, index=shared_subtree
    )
    left_instrs = (
        IRInstr(
            "MOV", IRValue(MemSpace.REG, name="ax", size=2),
            (left_shared,), size=2, addr=0x1000,
        ),
        IRInstr(
            "MOV", IRValue(MemSpace.REG, name="ax", size=2),
            (IRValue(MemSpace.REG, name="cx", size=2,
                     index=left_shared),),
            size=2, addr=0x1001,
        ),
    )
    right_instrs = (
        IRInstr(
            "MOV", IRValue(MemSpace.REG, name="ax", size=2),
            (right_shared,), size=2, addr=0x1000,
        ),
        IRInstr(
            "MOV", IRValue(MemSpace.REG, name="ax", size=2),
            (IRValue(MemSpace.REG, name="cx", size=2,
                     index=right_shared),),
            size=2, addr=0x1001,
        ),
    )
    left = IRBlock(addr=0x1000, instrs=left_instrs, refusals=(),
                   successor_addrs=())
    right = IRBlock(addr=0x1000, instrs=right_instrs, refusals=(),
                    successor_addrs=())
    assert dom._native_block_bound_8616(left, right) is False


def test_depth_exceeded_self_identical_block_still_refuses() -> None:
    """Depth-exceeded same-object terms refuse on every comparison."""
    deep: IRBinaryValue = IRBinaryValue("Iop_Add16", _const(1), _const(1), size=2)
    for _ in range(dom._NATIVE_BINDING_DEPTH_LIMIT_8616 + 8):
        deep = IRBinaryValue("Iop_Add16", deep, _const(1), size=2)
    row = IRInstr(
        "MOV", IRValue(MemSpace.REG, name="bx", size=2), (deep,),
        size=2, addr=0x1000,
    )
    block = IRBlock(addr=0x1000, instrs=(row,), refusals=(),
                    successor_addrs=())
    assert dom._native_block_bound_8616(block, block) is False
    assert dom._native_block_bound_8616(block, block) is False


def test_unknown_self_identical_dataclass_still_refuses() -> None:
    """An unowned dataclass is an unprovable field even compared to itself."""
    opaque = _OpaqueTerm(5)
    assert dom._native_term_equal_8616(opaque, opaque, 0) is False
    assert dom._native_term_equal_8616(opaque, _OpaqueTerm(5), 0) is False
    assert dom._native_term_equal_8616(opaque, _OpaqueTerm(6), 0) is False


def test_scalar_shortcut_cannot_accept_an_opaque_metaclass() -> None:
    """Builtin-looking metaclass equality grants no native binding evidence."""
    opaque = _OpaqueIntLikeTerm(9)
    assert dom._native_term_equal_8616(opaque, opaque, 0) is False
    assert dom._native_term_equal_8616((opaque,), (opaque,), 0) is False


def test_mutable_sequence_nodes_gain_no_acceptance() -> None:
    """Lists keep elementwise semantics: unprovable elements still refuse."""
    opaque = _OpaqueTerm(9)
    assert dom._native_term_equal_8616([opaque], [opaque], 0) is False
    same_list = [opaque]
    assert dom._native_term_equal_8616(same_list, same_list, 0) is False
    left = IRValue(MemSpace.REG, name="ax", size=2)
    right = IRValue(MemSpace.REG, name="ax", size=2)
    assert dom._native_term_equal_8616([left], [right], 0) is True
    assert dom._native_term_equal_8616([left], (right,), 0) is False


def test_capture_id_divergence_still_refuses() -> None:
    """``compare=False`` capture ids remain bound after memoization."""
    left = IRValue(MemSpace.TMP, size=2, source_tmp=7)
    right = IRValue(MemSpace.TMP, size=2, source_tmp=8)
    assert dom._native_value_equal_8616(left, right, 0) is False
    assert dom._native_value_equal_8616(left, left, 0) is True


@pytest.mark.parametrize("leaf", [None, True, False, 0, 1, "", "ax"])
def test_scalar_sequence_children_keep_the_depth_limit(leaf: object) -> None:
    """An exact scalar consumes child depth even when its parent is identical."""
    terms = (leaf,)
    limit = dom._NATIVE_BINDING_DEPTH_LIMIT_8616
    assert dom._native_term_equal_8616(terms, terms, limit - 1)
    assert not dom._native_term_equal_8616(terms, terms, limit)
    assert dom._native_term_equal_8616((), (), limit)


@pytest.mark.parametrize("left,right", [(True, 1), (False, 0), (1, "1"), (None, 0)])
def test_scalar_sequence_children_keep_exact_types(left: object, right: object) -> None:
    """Value equality cannot hide differently typed scalar sequence children."""
    assert not dom._native_term_equal_8616((left,), (right,), 0)
    assert not dom._native_term_equal_8616([left], [right], 0)


def test_memo_capacity_keeps_comparing_uncached_pairs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exhausted retention cannot accept later differences or grow memory."""
    monkeypatch.setattr(dom, "_NATIVE_BINDING_MEMO_MAX_PAIRS_8616", 1)
    memo = dom._NativeTermMemo8616()
    first_left, first_right = _const(1), _const(1)
    assert dom._native_term_equal_8616(first_left, first_right, 0, memo)
    assert len(memo._pins) == 1
    assert dom._native_term_equal_8616(_const(2), _const(2), 0, memo)
    assert not dom._native_term_equal_8616(_const(2), _const(3), 0, memo)
    assert len(memo._pins) == 1
    assert len(memo._true_depths) + len(memo._false_depths) == 1


def test_native_call_prefix_fits_only_executed_binding_budget(tmp_path: Path) -> None:
    """A partial native walk binds its consumed rows without billing a future suffix."""
    from tests.ir.test_callee_local_feasibility import world

    ctx, proof = world(tmp_path, bytes.fromhex("b80100bb0200c3"))
    artifact = proof.callee.coverage.artifact
    block = artifact.blocks[0]
    cutoff = block.addr
    prefix = tuple(row for row in block.instrs if row.addr == cutoff)
    assert 0 < len(prefix) < len(block.instrs)
    ctx.work_units = ctx.accounted_work_units = 0
    ctx.work_limit = 2 * len(prefix) + 1
    result = dom._simulate_path_block_8616(
        ctx, artifact, block, dom._PathState8616({}, dom.PathMemory8616()),
        stop_after=cutoff,
    )
    assert isinstance(result, dom._PathState8616), result
    assert result.registers["ax"] == 1
    assert "bx" not in result.registers
    assert ctx.work_units == ctx.work_limit
    assert ctx.raw_facts == {(block.addr, index) for index in range(len(prefix))}
    assert ctx.raw_facts == ctx.materialized_facts
    assert ctx.failures == 0


def test_native_prefix_mutation_stays_unbound(tmp_path: Path) -> None:
    """Prefix operands remain freshly authenticated before any row materializes."""
    from tests.ir.test_callee_local_feasibility import world

    ctx, proof = world(tmp_path, bytes.fromhex("b80100bb0200c3"))
    artifact = proof.callee.coverage.artifact
    block = artifact.blocks[0]
    row = next(row for row in block.instrs if row.addr == block.addr and row.args
               and isinstance(row.args[0], IRValue) and row.args[0].const is not None)
    object.__setattr__(row, "args", (replace(row.args[0], const=9),))
    result = dom._simulate_path_block_8616(
        ctx, artifact, block, dom._PathState8616({}, dom.PathMemory8616()),
        stop_after=block.addr,
    )
    assert result is dom.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    assert ctx.classified_facts
    assert not ctx.materialized_facts
    assert len(ctx.classified_facts) == ctx.failures


def test_prefix_binding_grants_no_whole_suffix_authority() -> None:
    """An unconsumed suffix never becomes authenticated by a prefix comparison."""
    native, block = _shared_dag_pair(8)
    changed = replace(block.instrs[6], args=(_const(99),))
    block = replace(block, instrs=(*block.instrs[:6], changed, *block.instrs[7:]))
    assert dom._native_block_bound_8616(native, block, stop_after=0x1002)
    assert not dom._native_block_bound_8616(native, block)
    assert not dom._native_block_bound_8616(
        native, replace(block, successor_addrs=(0x3000,)), stop_after=0x1002,
    )


def test_prefix_binding_rejects_missing_or_malformed_consumed_rows() -> None:
    """A premature cutoff cannot hide a deleted or undecodable native prefix row."""
    native, block = _shared_dag_pair(8)
    missing = replace(block, instrs=(block.instrs[0], *block.instrs[2:]))
    assert not dom._native_block_bound_8616(native, missing, stop_after=0x1002)
    malformed = replace(block.instrs[1], addr=None)
    malformed_block = replace(block, instrs=(block.instrs[0], malformed, *block.instrs[2:]))
    assert not dom._native_block_bound_8616(native, malformed_block, stop_after=0x1002)
    assert not dom._native_block_bound_8616(native, block, stop_after=0xFFF)
