"""Focused regression for the canonical shared-DAG IR source binding.

Covers ``inertia/ir/source_graph_binding.py`` and its consumption through
``entry_jump_domain._canonical_source_8616``/``_source_digest_8616``:

- shared expression DAGs encode as a linear interned node table and the
  canonical string is identical for structurally equal shared and
  deep-copied/unshared DAGs (object identity is never a serialized value),
- the encoding is deterministic across fresh interpreters and hash seeds,
- every owned field — including ``compare=False`` provenance such as
  ``source_tmp``, ``memory_access_insn`` and ``width_bits`` — changes the
  canonical form, as do ordering changes,
- cyclic graphs, mutable containers, opaque payloads and unknown node
  subclasses refuse loudly instead of degrading,
- recorded ``v1`` bindings cannot replay: the ``v2`` marker changes every
  recomputed digest, so stale proof application refuses.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import fields, replace
from pathlib import Path

import pytest

import inertia.ir.entry_jump_domain as ejd
from inertia.ir.core import (
    AddressStatus,
    IRActiveUnary8616,
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRCallOutputProvenance8616,
    IRCallOutputShape8616,
    IRCallStackEffect8616,
    IRCondition,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.instruction_origin import IRInstructionOrigin8616
from inertia.ir.source_graph_binding import (
    SOURCE_GRAPH_FORMAT_8616,
    SourceGraphSerializationError8616,
    canonical_source_graph_8616,
    source_graphs_equal_8616,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_operation_local_graph_equality_shares_nodes_and_rechecks_mutations(monkeypatch) -> None:
    """One comparison shares its traversal; the next must see live mutations."""
    import inertia.ir.source_graph_binding as graph

    blocks = _rich_blocks()
    built = 0
    original = graph._record_key_8616

    def record_key(record, field_orders=None):
        nonlocal built
        built += 1
        return original(record, field_orders)

    monkeypatch.setattr(graph, "_record_key_8616", record_key)
    graph.canonical_source_graph_8616(0x100, blocks)
    single_pass = built
    assert single_pass > 0
    built = 0
    assert graph.source_graphs_equal_8616(0x100, blocks, 0x100, blocks)
    assert built == single_pass
    baseline = copy.deepcopy(blocks)
    value = blocks[0].instrs[0].dst
    object.__setattr__(value, 'source_tmp', 987654)
    assert not graph.source_graphs_equal_8616(0x100, baseline, 0x100, blocks)


def test_old_supported_deep_expression_remains_serializable() -> None:
    """Canonical binding must not lower the old valid expression-depth limit."""
    leaf = IRValue(MemSpace.CONST, const=1, size=2)
    expression: IRValue | IRBinaryValue = leaf
    for _ in range(200):
        expression = IRBinaryValue("add", expression, leaf, 2)
    blocks = (IRBlock(0x1000, (IRInstr("ASSIGN", leaf, (expression,)),)),)
    assert json.dumps([block.to_dict() for block in blocks])
    encoded = json.loads(canonical_source_graph_8616(0x1000, blocks))
    assert len(encoded["nodes"]) == 203


def test_malformed_child_container_refuses_before_traversal() -> None:
    """A corrupt typed container must not escape as an incidental iterator error."""
    block = replace(IRBlock(0x1000), instrs=None)
    with pytest.raises(SourceGraphSerializationError8616, match=r"IRBlock\.instrs"):
        canonical_source_graph_8616(0x1000, (block,))


def _tmp(ident: int) -> IRValue:
    """Build a temporary value pinned to its captured source identity."""
    return IRValue(
        space=MemSpace.TMP, offset=ident, size=2, source_tmp=ident,
    )


def _const(value: int) -> IRValue:
    """Build a constant value."""
    return IRValue(space=MemSpace.CONST, const=value, size=2)


def _rich_address() -> IRAddress:
    """Build an address exercising every owned address field."""
    return IRAddress(
        space=MemSpace.SS,
        base=("ss", "bp"),
        offset=-4,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
        expr=("ss", "bp"),
        version=1,
        base_values=(
            IRValue(space=MemSpace.REG, name="ss", size=2),
            IRValue(space=MemSpace.REG, name="bp", size=2),
        ),
    )


def _rich_value() -> IRValue:
    """Build a value exercising every owned value field."""
    return IRValue(
        space=MemSpace.DS,
        name="rich",
        offset=8,
        const=None,
        size=2,
        version=3,
        expr=("d",),
        index=_tmp(9),
        index_shift=1,
        memory_access_size=2,
        memory_access_insn=0x55,
        source_tmp=11,
        call_output=IRCallOutputProvenance8616(
            callsite_addr=0x99,
            target_addr=0x200,
            shape=IRCallOutputShape8616.DX_AX,
        ),
        active_unary=IRActiveUnary8616(
            op="Iop_Not16", operand=_tmp(12), result_bits=16,
        ),
    )


def _rich_blocks() -> tuple[IRBlock, IRBlock]:
    """Build a two-block census exercising every owned node kind."""
    value = _rich_value()
    binary = IRBinaryValue(op="Add16", lhs=_tmp(1), rhs=_tmp(2), size=2)
    condition = IRCondition(
        op="slt", args=(_tmp(7), _const(3)), expr=("<",), width_bits=16,
    )
    effect = IRCallStackEffect8616(
        net_stack_delta=0,
        preserved_ranges=(_rich_address(),),
        escaped_ranges=(),
        complete=True,
        bp_preserved=True,
    )
    origin = IRInstructionOrigin8616(
        block_addr=0x100,
        statement_index=2,
        address_tmp=7,
        is_block_next=False,
        block_next_tmp=None,
        is_instruction_mark=False,
    )
    first = IRInstr(
        op="STORE",
        dst=_tmp(20),
        args=(binary, value, _rich_address(), condition),
        size=4,
        addr=0x100,
        call_stack_effect=effect,
        origin=origin,
    )
    second = IRInstr(op="CALL", dst=None, args=(value,), size=2, addr=0x104)
    head = IRBlock(
        addr=0x100,
        instrs=(first, second),
        refusals=(IRRefusal(kind="k", detail="d", block_addr=0x100),),
        successor_addrs=(0x200, 0x300),
    )
    tail = IRBlock(addr=0x200, instrs=(), successor_addrs=())
    return (head, tail)


def _i0(blocks: tuple[IRBlock, ...]) -> IRInstr:
    """Return the first instruction of the head block."""
    return blocks[0].instrs[0]


def _put_instr(
    blocks: tuple[IRBlock, ...], instr: IRInstr,
) -> tuple[IRBlock, ...]:
    """Rebuild the census replacing the head block's first instruction."""
    head = blocks[0]
    return (replace(head, instrs=(instr, *head.instrs[1:])), *blocks[1:])


def _put_arg(
    blocks: tuple[IRBlock, ...], index: int, arg: object,
) -> tuple[IRBlock, ...]:
    """Rebuild the census replacing one argument of the first instruction."""
    instr = _i0(blocks)
    args = list(instr.args)
    args[index] = arg
    return _put_instr(blocks, replace(instr, args=tuple(args)))


def _canon(blocks: tuple[IRBlock, ...]) -> str:
    """Encode the fixture census through the private consumer path."""
    return ejd._canonical_source_8616(0x100, blocks)


def test_shared_dag_encodes_linear_and_unshared_copy_matches() -> None:
    """A depth-18 shared binary DAG interns to a linear node table, and a
    structurally equal fully unshared tree produces the identical string."""
    leaf = _tmp(3)
    shared = leaf
    for _ in range(18):
        shared = IRBinaryValue("Add16", shared, shared, size=2)
    block = IRBlock(
        addr=0x10, instrs=(IRInstr(op="R", dst=None, args=(shared,)),),
    )
    canonical = canonical_source_graph_8616(0x10, (block,))
    node_count = len(json.loads(canonical)["nodes"])
    # 19 value/binary records + 1 instr + 1 block; a tree encoding would
    # need 2**18 - 1 binary records alone.
    assert node_count == 21

    shallow = leaf
    for _ in range(10):
        shallow = IRBinaryValue("Add16", shallow, shallow, size=2)

    def unshare(node: IRValue | IRBinaryValue) -> IRValue | IRBinaryValue:
        """Rebuild the DAG with every shared subtree replaced by copies."""
        if type(node) is IRBinaryValue:
            return IRBinaryValue(
                node.op, unshare(node.lhs), unshare(node.rhs), size=node.size,
            )
        return node

    unshared = unshare(shallow)
    small_block = IRBlock(
        addr=0x10, instrs=(IRInstr(op="R", dst=None, args=(unshared,)),),
    )
    small_shared_block = IRBlock(
        addr=0x10, instrs=(IRInstr(op="R", dst=None, args=(shallow,)),),
    )
    assert canonical_source_graph_8616(0x10, (small_shared_block,)) == (
        canonical_source_graph_8616(0x10, (small_block,))
    )


def test_deep_copy_and_repeated_encoding_are_identical() -> None:
    """Deep copies and fresh encoder instances agree; ids never serialize."""
    blocks = _rich_blocks()
    baseline = _canon(blocks)
    assert _canon(copy.deepcopy(blocks)) == baseline
    assert _canon(blocks) == baseline
    assert str(id(blocks[0])) not in baseline


_FRESH_SNIPPET = "\n".join((
    "from inertia.ir.core import (",
    "    IRBinaryValue, IRBlock, IRInstr, IRValue, MemSpace,",
    ")",
    "from inertia.ir.source_graph_binding import (",
    "    canonical_source_graph_8616,",
    ")",
    "leaf = IRValue(space=MemSpace.TMP, offset=7, size=2, source_tmp=7)",
    "node = leaf",
    "for _ in range(9):",
    "    node = IRBinaryValue('Add16', node, node, size=2)",
    "block = IRBlock(",
    "    addr=4096,",
    "    instrs=(IRInstr(op='GET', dst=None, args=(node, leaf)),),",
    "    successor_addrs=(8192,),",
    ")",
    "print(canonical_source_graph_8616(4096, (block,)))",
))


@pytest.mark.parametrize("seed", ["0", "1"])
def test_fresh_process_encoding_is_deterministic(seed: str) -> None:
    """A fresh interpreter under another hash seed emits identical bytes."""
    proc = subprocess.run(
        [sys.executable, "-c", _FRESH_SNIPPET],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONHASHSEED": seed},
        cwd=_REPO_ROOT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    proc2 = subprocess.run(
        [sys.executable, "-c", _FRESH_SNIPPET],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONHASHSEED": "0"},
        cwd=_REPO_ROOT,
        check=False,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert proc.stdout == proc2.stdout


def _mutations() -> (
    tuple[tuple[str, Callable[[tuple[IRBlock, ...]], tuple[IRBlock, ...]]], ...]
):
    """One census mutation per owned field; each must change the binding."""
    return (
        ("block.addr", lambda bs: (replace(bs[0], addr=0x999), bs[1])),
        ("block.instrs.extra", lambda bs: (
            replace(bs[0], instrs=(*bs[0].instrs, _i0(bs))), bs[1]),
        ),
        ("block.instrs.order", lambda bs: (
            replace(bs[0], instrs=bs[0].instrs[::-1]), bs[1]),
        ),
        ("block.refusals.kind", lambda bs: (
            replace(
                bs[0],
                refusals=(replace(bs[0].refusals[0], kind="other"),),
            ), bs[1]),
        ),
        ("block.refusals.detail", lambda bs: (
            replace(
                bs[0],
                refusals=(replace(bs[0].refusals[0], detail="x"),),
            ), bs[1]),
        ),
        ("block.refusals.block_addr", lambda bs: (
            replace(
                bs[0],
                refusals=(replace(bs[0].refusals[0], block_addr=None),),
            ), bs[1]),
        ),
        ("block.successor_addrs.order", lambda bs: (
            replace(bs[0], successor_addrs=bs[0].successor_addrs[::-1]),
            bs[1]),
        ),
        ("block.successor_addrs.drop", lambda bs: (
            replace(bs[0], successor_addrs=bs[0].successor_addrs[:1]), bs[1]),
        ),
        ("instr.op", lambda bs: _put_instr(
            bs, replace(_i0(bs), op="NOP"))),
        ("instr.dst.none", lambda bs: _put_instr(
            bs, replace(_i0(bs), dst=None))),
        ("instr.dst.value", lambda bs: _put_instr(
            bs, replace(_i0(bs), dst=_tmp(99)))),
        ("instr.args.order", lambda bs: _put_instr(
            bs, replace(_i0(bs), args=_i0(bs).args[::-1]))),
        ("instr.size", lambda bs: _put_instr(
            bs, replace(_i0(bs), size=8))),
        ("instr.addr.none", lambda bs: _put_instr(
            bs, replace(_i0(bs), addr=None))),
        ("instr.addr.value", lambda bs: _put_instr(
            bs, replace(_i0(bs), addr=0x101))),
        ("effect.net_stack_delta", lambda bs: _put_instr(
            bs, replace(
                _i0(bs),
                call_stack_effect=replace(
                    _i0(bs).call_stack_effect, net_stack_delta=2,
                )))),
        ("effect.complete", lambda bs: _put_instr(
            bs, replace(
                _i0(bs),
                call_stack_effect=replace(
                    _i0(bs).call_stack_effect, complete=False,
                )))),
        ("effect.bp_preserved", lambda bs: _put_instr(
            bs, replace(
                _i0(bs),
                call_stack_effect=replace(
                    _i0(bs).call_stack_effect, bp_preserved=False,
                )))),
        ("effect.preserved_ranges", lambda bs: _put_instr(
            bs, replace(
                _i0(bs),
                call_stack_effect=replace(
                    _i0(bs).call_stack_effect,
                    preserved_ranges=(
                        replace(_rich_address(), offset=-8),
                    ),
                )))),
        ("effect.escaped_ranges", lambda bs: _put_instr(
            bs, replace(
                _i0(bs),
                call_stack_effect=replace(
                    _i0(bs).call_stack_effect,
                    escaped_ranges=(_rich_address(),),
                )))),
        ("origin.statement_index", lambda bs: _put_instr(
            bs, replace(
                _i0(bs),
                origin=replace(_i0(bs).origin, statement_index=3)))),
        ("origin.address_tmp", lambda bs: _put_instr(
            bs, replace(
                _i0(bs), origin=replace(_i0(bs).origin, address_tmp=None)))),
        ("origin.is_block_next", lambda bs: _put_instr(
            bs, replace(
                _i0(bs),
                origin=replace(_i0(bs).origin, is_block_next=True)))),
        ("origin.block_next_tmp", lambda bs: _put_instr(
            bs, replace(
                _i0(bs),
                origin=replace(_i0(bs).origin, block_next_tmp=4)))),
        ("origin.is_instruction_mark", lambda bs: _put_instr(
            bs, replace(
                _i0(bs),
                origin=replace(_i0(bs).origin, is_instruction_mark=True)))),
        ("value.space", lambda bs: _put_arg(
            bs, 1, replace(_i0(bs).args[1], space=MemSpace.ES))),
        ("value.name.none", lambda bs: _put_arg(
            bs, 1, replace(_i0(bs).args[1], name=None))),
        ("value.offset", lambda bs: _put_arg(
            bs, 1, replace(_i0(bs).args[1], offset=9))),
        ("value.const.none_vs_zero", lambda bs: _put_arg(
            bs, 1, replace(_i0(bs).args[1], const=0))),
        ("value.size", lambda bs: _put_arg(
            bs, 1, replace(_i0(bs).args[1], size=4))),
        ("value.version", lambda bs: _put_arg(
            bs, 1, replace(_i0(bs).args[1], version=4))),
        ("value.expr.none_vs_empty", lambda bs: _put_arg(
            bs, 1, replace(_i0(bs).args[1], expr=None))),
        ("value.index", lambda bs: _put_arg(
            bs, 1, replace(_i0(bs).args[1], index=_tmp(10)))),
        ("value.index_shift", lambda bs: _put_arg(
            bs, 1, replace(_i0(bs).args[1], index_shift=2))),
        ("value.memory_access_size", lambda bs: _put_arg(
            bs, 1, replace(_i0(bs).args[1], memory_access_size=4))),
        ("value.memory_access_insn", lambda bs: _put_arg(
            bs, 1, replace(_i0(bs).args[1], memory_access_insn=0x56))),
        ("value.source_tmp", lambda bs: _put_arg(
            bs, 1, replace(_i0(bs).args[1], source_tmp=13))),
        ("call_output.callsite_addr", lambda bs: _put_arg(
            bs, 1, replace(
                _i0(bs).args[1],
                call_output=replace(
                    _i0(bs).args[1].call_output, callsite_addr=0x9A,
                )))),
        ("call_output.target_addr", lambda bs: _put_arg(
            bs, 1, replace(
                _i0(bs).args[1],
                call_output=replace(
                    _i0(bs).args[1].call_output, target_addr=0x201,
                )))),
        ("call_output.shape", lambda bs: _put_arg(
            bs, 1, replace(
                _i0(bs).args[1],
                call_output=replace(
                    _i0(bs).args[1].call_output,
                    shape=IRCallOutputShape8616.AX,
                )))),
        ("active_unary.op", lambda bs: _put_arg(
            bs, 1, replace(
                _i0(bs).args[1],
                active_unary=replace(
                    _i0(bs).args[1].active_unary, op="Iop_Not8",
                )))),
        ("active_unary.result_bits", lambda bs: _put_arg(
            bs, 1, replace(
                _i0(bs).args[1],
                active_unary=replace(
                    _i0(bs).args[1].active_unary, result_bits=8,
                )))),
        ("active_unary.operand", lambda bs: _put_arg(
            bs, 1, replace(
                _i0(bs).args[1],
                active_unary=replace(
                    _i0(bs).args[1].active_unary, operand=_tmp(13),
                )))),
        ("binary.op", lambda bs: _put_arg(
            bs, 0, replace(_i0(bs).args[0], op="Sub16"))),
        ("binary.size", lambda bs: _put_arg(
            bs, 0, replace(_i0(bs).args[0], size=4))),
        ("binary.operands.swap", lambda bs: _put_arg(
            bs, 0, replace(
                _i0(bs).args[0],
                lhs=_i0(bs).args[0].rhs, rhs=_i0(bs).args[0].lhs))),
        ("address.space", lambda bs: _put_arg(
            bs, 2, replace(_i0(bs).args[2], space=MemSpace.DS))),
        ("address.base", lambda bs: _put_arg(
            bs, 2, replace(_i0(bs).args[2], base=("ss",)))),
        ("address.offset", lambda bs: _put_arg(
            bs, 2, replace(_i0(bs).args[2], offset=-6))),
        ("address.size", lambda bs: _put_arg(
            bs, 2, replace(_i0(bs).args[2], size=4))),
        ("address.status", lambda bs: _put_arg(
            bs, 2, replace(
                _i0(bs).args[2], status=AddressStatus.PROVISIONAL))),
        ("address.segment_origin", lambda bs: _put_arg(
            bs, 2, replace(
                _i0(bs).args[2],
                segment_origin=SegmentOrigin.DEFAULTED))),
        ("address.expr", lambda bs: _put_arg(
            bs, 2, replace(_i0(bs).args[2], expr=None))),
        ("address.version", lambda bs: _put_arg(
            bs, 2, replace(_i0(bs).args[2], version=None))),
        ("address.base_values", lambda bs: _put_arg(
            bs, 2, replace(_i0(bs).args[2], base_values=()))),
        ("condition.op", lambda bs: _put_arg(
            bs, 3, replace(_i0(bs).args[3], op="sle"))),
        ("condition.args", lambda bs: _put_arg(
            bs, 3, replace(
                _i0(bs).args[3], args=(_tmp(7), _const(4))))),
        ("condition.expr", lambda bs: _put_arg(
            bs, 3, replace(_i0(bs).args[3], expr=("<=",)))),
        ("condition.width_bits", lambda bs: _put_arg(
            bs, 3, replace(_i0(bs).args[3], width_bits=None))),
        ("condition.width_bits.value", lambda bs: _put_arg(
            bs, 3, replace(_i0(bs).args[3], width_bits=8))),
        ("blocks.order", lambda bs: (bs[1], bs[0])),
        ("function_addr", lambda bs: bs),
    )


@pytest.mark.parametrize(
    "mutate", [mutation for _, mutation in _mutations()],
    ids=[name for name, _ in _mutations()],
)
def test_every_field_mutation_invalidates_binding(
    mutate: Callable[[tuple[IRBlock, ...]], tuple[IRBlock, ...]],
) -> None:
    """Mutating any owned field changes canonical form and digest — the
    negative control for proof replay against stale input."""
    blocks = _rich_blocks()
    baseline = _canon(blocks)
    mutated = mutate(blocks)
    if mutated is blocks:
        assert ejd._canonical_source_8616(0x101, blocks) != baseline
        assert not source_graphs_equal_8616(0x100, blocks, 0x101, blocks)
        return
    assert _canon(mutated) != baseline
    assert not source_graphs_equal_8616(0x100, blocks, 0x100, mutated)
    assert source_graphs_equal_8616(0x100, mutated, 0x100, copy.deepcopy(mutated))
    assert ejd._source_digest_8616(0x100, mutated) != (
        ejd._source_digest_8616(0x100, blocks)
    )


@pytest.mark.parametrize('mode', ['empty', 'copy', 'reorder', 'list', 'duplicate', 'address'])
def test_graph_equality_matches_canonical_documents(mode):
    """Root order, multiplicity, addresses and historical root lists agree."""
    left = _rich_blocks()
    right = copy.deepcopy(left)
    right_addr = 0x100
    if mode == 'empty':
        left = right = ()
    elif mode == 'reorder':
        right = tuple(reversed(right))
    elif mode == 'list':
        right = list(right)
    elif mode == 'duplicate':
        right = (*right, right[0])
    elif mode == 'address':
        right_addr += 1
    assert source_graphs_equal_8616(0x100, left, right_addr, right) == (
        canonical_source_graph_8616(0x100, left) == canonical_source_graph_8616(right_addr, right)
    )


@pytest.mark.parametrize('bad', ['cycle', 'bool', 'float', 'mutable', 'opaque', 'subclass', 'enum'])
@pytest.mark.parametrize('different_head', [False, True])
def test_graph_equality_never_shortcuts_invalid_surfaces(bad, different_head):
    """Malformed self graphs and unequal-head right sides still refuse."""
    node = _tmp(3)
    if bad == 'cycle':
        object.__setattr__(node, 'index', node)
    elif bad == 'bool':
        object.__setattr__(node, 'offset', True)
    elif bad == 'float':
        object.__setattr__(node, 'offset', 3.0)
    elif bad == 'mutable':
        object.__setattr__(node, 'expr', ['x'])
    elif bad == 'opaque':
        node = object()
    elif bad == 'subclass':
        class ForeignValue(IRValue):
            pass
        node = ForeignValue(MemSpace.TMP, offset=3)
    else:
        object.__setattr__(node, 'space', 'tmp')
    malformed = (IRBlock(0x100, (IRInstr('ASSIGN', None, (node,)),)),)
    with pytest.raises(SourceGraphSerializationError8616):
        canonical_source_graph_8616(0x100, malformed)
    left = _rich_blocks() if different_head else malformed
    with pytest.raises(SourceGraphSerializationError8616):
        source_graphs_equal_8616(0x100, left, 0x101 if different_head else 0x100, malformed)


def test_none_zero_false_and_string_stay_distinct() -> None:
    """Typed scalar kinds never collapse inside a node record."""
    blocks = _rich_blocks()
    baseline = _canon(blocks)
    value = _i0(blocks).args[1]
    for changed in (
        replace(value, name=""),          # name None-vs-text and ""-vs-"rich"
        replace(value, version=0),        # None vs 0
        replace(value, expr=()),          # absent vs empty tuple
    ):
        assert _canon(_put_arg(blocks, 1, changed)) != baseline
    origin = _i0(blocks).origin
    assert _canon(_put_instr(
        blocks, replace(
            _i0(blocks), origin=replace(origin, block_next_tmp=0)),
    )) != baseline


def test_unknown_mutable_and_opaque_payloads_refuse() -> None:
    """Subclasses, mutable containers, and opaque payloads fail loudly."""
    blocks = _rich_blocks()
    instr = _i0(blocks)

    class ForeignValue(IRValue):
        """An unknown node subclass; it must not gain canonical acceptance."""

    foreign = ForeignValue(space=MemSpace.TMP, offset=5, size=2)
    with pytest.raises(SourceGraphSerializationError8616):
        _canon(_put_arg(blocks, 0, foreign))
    with pytest.raises(SourceGraphSerializationError8616):
        _canon(_put_arg(blocks, 0, {"opaque": True}))
    with pytest.raises(SourceGraphSerializationError8616):
        _canon(_put_arg(blocks, 0, [1, 2]))
    with pytest.raises(SourceGraphSerializationError8616):
        _canon(_put_arg(blocks, 0, _rich_address().__class__))

    mutable_expr = _tmp(5)
    object.__setattr__(mutable_expr, "expr", ["a"])
    with pytest.raises(SourceGraphSerializationError8616):
        _canon(_put_arg(blocks, 0, mutable_expr))

    mutable_instrs = replace(
        blocks[0], instrs=instr.instrs if hasattr(instr, "instrs") else (),
    )
    object.__setattr__(mutable_instrs, "instrs", list(blocks[0].instrs))
    with pytest.raises(SourceGraphSerializationError8616):
        _canon((mutable_instrs,))

    object.__setattr__(mutable_instrs, "instrs", blocks[0].instrs)
    object.__setattr__(mutable_instrs, "successor_addrs", [0x200])
    with pytest.raises(SourceGraphSerializationError8616):
        _canon((mutable_instrs,))

    with pytest.raises(SourceGraphSerializationError8616):
        _canon((instr,))  # type: ignore[arg-type]

    bool_in_int = _tmp(6)
    object.__setattr__(bool_in_int, "offset", True)
    with pytest.raises(SourceGraphSerializationError8616):
        _canon(_put_arg(blocks, 0, bool_in_int))

    int_in_bool = replace(
        _i0(blocks).origin,
        is_block_next=1,  # type: ignore[arg-type]
    )
    with pytest.raises(SourceGraphSerializationError8616):
        _canon(_put_instr(blocks, replace(_i0(blocks), origin=int_in_bool)))

    str_in_int = _tmp(7)
    object.__setattr__(str_in_int, "offset", "7")
    with pytest.raises(SourceGraphSerializationError8616):
        _canon(_put_arg(blocks, 0, str_in_int))


def test_cyclic_value_graph_refuses() -> None:
    """A self-referential value refuses instead of recursing forever."""
    cyclic = _tmp(1)
    object.__setattr__(cyclic, "index", cyclic)
    block = IRBlock(
        addr=0x1, instrs=(IRInstr(op="X", dst=None, args=(cyclic,)),),
    )
    with pytest.raises(SourceGraphSerializationError8616):
        _canon((block,))


def test_v1_recorded_binding_refuses_on_replay() -> None:
    """A binding recorded under the v1 tree encoding can never recompute:
    the v2 marker and node table change every canonical string and digest."""
    blocks = _rich_blocks()
    v1_payload = json.dumps(
        {
            "format": "entry_jump_domain_source_binding_8616/v1",
            "function_addr": 0x100,
            "blocks": [block.to_dict() for block in blocks],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    v1_digest = hashlib.sha256(v1_payload.encode("utf-8")).hexdigest()
    canonical = _canon(blocks)
    assert json.loads(canonical)["format"] == SOURCE_GRAPH_FORMAT_8616
    assert SOURCE_GRAPH_FORMAT_8616.endswith("/v2")
    assert "v1" not in json.loads(canonical)["format"]
    assert canonical != v1_payload
    assert ejd._source_digest_8616(0x100, blocks) != v1_digest


def test_owned_schema_field_sets_are_detected() -> None:
    """Adding a field to an owned contract fails this test before any
    silent canonical-form gap can hide it."""
    expected = {
        IRValue: {
            "space", "name", "offset", "const", "size", "version", "expr",
            "index", "index_shift", "memory_access_size",
            "memory_access_insn", "source_tmp", "call_output", "active_unary",
        },
        IRBinaryValue: {"op", "lhs", "rhs", "size"},
        IRActiveUnary8616: {"op", "operand", "result_bits"},
        IRCallOutputProvenance8616: {
            "callsite_addr", "target_addr", "shape",
        },
        IRAddress: {
            "space", "base", "offset", "size", "status", "segment_origin",
            "expr", "version", "base_values",
        },
        IRCondition: {"op", "args", "expr", "width_bits"},
        IRInstr: {
            "op", "dst", "args", "size", "addr", "call_stack_effect",
            "origin",
        },
        IRCallStackEffect8616: {
            "net_stack_delta", "preserved_ranges", "escaped_ranges",
            "complete", "bp_preserved", "stack_coordinates", "scoped_coordinates",
        },
        IRInstructionOrigin8616: {
            "block_addr", "statement_index", "address_tmp", "is_block_next",
            "block_next_tmp", "is_instruction_mark",
        },
        IRRefusal: {"kind", "detail", "block_addr"},
        IRBlock: {"addr", "instrs", "refusals", "successor_addrs"},
    }
    for contract, field_names in expected.items():
        assert {f.name for f in fields(contract)} == field_names


def test_record_key_matches_json_reference_for_all_owned_fields(monkeypatch) -> None:
    """The optimization changes intern lookup only, never canonical proof bytes."""
    import inertia.ir.source_graph_binding as owner
    surfaces = [_rich_blocks(), copy.deepcopy(_rich_blocks())]
    surfaces.extend(mutate(_rich_blocks()) for _, mutate in _mutations())
    optimized = [canonical_source_graph_8616(0x100, blocks) for blocks in surfaces]
    monkeypatch.setattr(owner, '_record_key_8616',
                        lambda record, _orders=None: json.dumps(record, sort_keys=True, separators=(',', ':')))
    assert [canonical_source_graph_8616(0x100, blocks) for blocks in surfaces] == optimized


def test_record_key_retains_primitive_and_sequence_distinctions() -> None:
    """Sorted fields, ordered lists and boolean tags match the old JSON keys."""
    from inertia.ir.source_graph_binding import _record_key_8616
    records = [{'value': item} for item in (None, 0, False, 1, True, '1', [1], [True], [])]
    keys = [_record_key_8616(record) for record in records]
    assert len(set(keys)) == len(records)
    assert _record_key_8616({'a': 1, 'b': [2, 3]}) == _record_key_8616({'b': [2, 3], 'a': 1})
    assert _record_key_8616({'a': [2, 3]}) != _record_key_8616({'a': [3, 2]})
    with pytest.raises(SourceGraphSerializationError8616):
        _record_key_8616({'value': 1.0})


def test_record_field_orders_keep_schema_and_current_values() -> None:
    """Order reuse never merges different field sets or caches mutable values."""
    from inertia.ir.source_graph_binding import _record_key_8616

    orders = {}
    record = {'a': 1, 'b': [2, 3]}
    first = _record_key_8616(record, orders)
    assert first == _record_key_8616({'b': [2, 3], 'a': 1}, orders)
    assert first != _record_key_8616({'a': 1, 'c': [2, 3]}, orders)
    record['b'].append(4)
    assert first != _record_key_8616(record, orders)
    assert first == _record_key_8616({'a': 1, 'b': [2, 3]}, orders)
    assert _record_key_8616({}, orders) != _record_key_8616({'a': None}, orders)


def test_record_key_uses_string_subclass_contents_not_custom_methods(monkeypatch) -> None:
    """JSON-compatible string subclass contents cannot forge an intern collision."""
    import inertia.ir.source_graph_binding as owner
    class MisleadingString(str):
        def __str__(self):
            return 'wrong'
        def __eq__(self, other):
            return True
        def __hash__(self):
            return 0
    assert owner._record_key_8616({'name': MisleadingString('right')}) == owner._record_key_8616({'name': 'right'})
    blocks = (IRBlock(0x100, (IRInstr(MisleadingString('ASSIGN'), _tmp(1), (_const(2),)),)),)
    encoded = canonical_source_graph_8616(0x100, blocks)
    monkeypatch.setattr(owner, '_record_key_8616',
                        lambda record, _orders=None: json.dumps(record, sort_keys=True, separators=(',', ':')))
    assert canonical_source_graph_8616(0x100, blocks) == encoded
