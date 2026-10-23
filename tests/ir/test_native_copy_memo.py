"""Seeded deepcopy memo coverage for detached native IR nodes."""

import copy
from copy import deepcopy
from typing import cast

import pytest

from inertia.ir.core import (
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
)
from inertia.ir.instruction_origin import IRInstructionOrigin8616
from inertia.ir.native_copy_memo import seed_native_copy_memo_8616

pytestmark = pytest.mark.decompiler


def test_shared_instruction_args_tuple_preserved() -> None:
    """Two fields sharing a tuple still share one detached tuple."""
    value = IRValue(space=MemSpace.REG, name="ax", size=2)
    shared = (value,)
    blocks = (IRBlock(addr=1, instrs=(
        IRInstr(op="A", dst=None, args=shared),
        IRInstr(op="B", dst=None, args=shared),
    )),)
    plain = deepcopy(blocks)
    assert plain[0].instrs[0].args is plain[0].instrs[1].args
    actual = deepcopy(blocks, seed_native_copy_memo_8616(blocks))
    assert actual[0].instrs[0].args is actual[0].instrs[1].args
    assert actual[0].instrs[0].args is not shared


def test_tuple_list_cycle_preserves_tuple_identity() -> None:
    """Generic mutable payloads can lead back into an owned tuple field."""
    payload: list[object] = []
    shared = (payload,)
    payload.append(shared)
    instr = IRInstr(op="X", dst=None, args=())
    object.__setattr__(instr, "args", shared)
    blocks = (IRBlock(addr=1, instrs=(instr,)),)
    plain = deepcopy(blocks)
    assert plain[0].instrs[0].args[0][0] is plain[0].instrs[0].args
    actual = deepcopy(blocks, seed_native_copy_memo_8616(blocks))
    copied = actual[0].instrs[0].args
    assert copied[0][0] is copied
    assert copied is not shared
    assert copied[0] is not payload

_OWNED_NODE_TYPES = (
    IRValue, IRBinaryValue, IRAddress, IRCondition, IRInstr, IRBlock,
    IRRefusal, IRCallStackEffect8616, IRActiveUnary8616,
    IRCallOutputProvenance8616, IRInstructionOrigin8616,
)


def _sample_blocks() -> tuple[IRBlock, ...]:
    shared = IRValue(
        space=MemSpace.REG, name="ax", size=2,
        memory_access_insn=3, source_tmp=9,
    )
    index_leaf = IRValue(space=MemSpace.TMP, name="t7", size=8, expr=("ld", "t7"))
    indexed = IRValue(space=MemSpace.SS, name="bp", offset=-4, size=2, index=index_leaf)
    const_leaf = IRValue(space=MemSpace.CONST, const=4, size=2)
    binary = IRBinaryValue(op="add", lhs=shared, rhs=const_leaf, size=2)
    address = IRAddress(
        space=MemSpace.DS, base=("ds", "si"), offset=2, size=2,
        base_values=(shared, index_leaf),
    )
    condition = IRCondition(
        op="slt", args=(binary, const_leaf), expr=("lt",), width_bits=16,
    )
    instr = IRInstr(
        op="MOV", dst=shared, args=(indexed, address, condition), size=2, addr=0x100,
    )
    return (IRBlock(addr=0x100, instrs=(instr,), successor_addrs=(0x102,)),)


def test_seeded_memo_detaches_every_exact_owned_node() -> None:
    """Every reachable owned node gets a detached clone in the memo."""
    blocks = _sample_blocks()
    memo = seed_native_copy_memo_8616(blocks)
    instr = blocks[0].instrs[0]
    indexed, address, condition = instr.args
    binary = condition.args[0]
    nodes = (
        blocks[0], instr, instr.dst, indexed, indexed.index, address,
        condition, binary, condition.args[1],
    )
    for node in nodes:
        clone = memo[id(node)]
        assert clone is not node
        assert clone == node
        assert type(clone) is type(node)
    clone_instr = memo[id(instr)]
    assert clone_instr.dst is memo[id(blocks[0].instrs[0].args[1].base_values[0])]


def test_seeded_deepcopy_matches_ordinary_deepcopy() -> None:
    """A seeded copy equals ordinary deepcopy including compare=False fields."""
    blocks = _sample_blocks()
    plain = deepcopy(blocks)
    seeded = deepcopy(blocks, seed_native_copy_memo_8616(blocks))
    assert seeded == plain == blocks
    instr = seeded[0].instrs[0]
    plain_instr = plain[0].instrs[0]
    assert instr.dst.memory_access_insn == plain_instr.dst.memory_access_insn == 3
    assert instr.dst.source_tmp == plain_instr.dst.source_tmp == 9
    assert instr.args[2].width_bits == plain_instr.args[2].width_bits == 16
    for source_leaf, seeded_leaf in (
        (blocks[0].instrs[0].dst, instr.dst),
        (blocks[0].instrs[0].args[0].index, instr.args[0].index),
        (blocks[0].instrs[0].args[2].args[1], instr.args[2].args[1]),
    ):
        assert seeded_leaf is not source_leaf
        assert seeded_leaf == source_leaf


def test_shared_leaf_copies_to_one_new_node() -> None:
    """Every reference to one source leaf resolves to the same clone."""
    blocks = _sample_blocks()
    memo = seed_native_copy_memo_8616(blocks)
    seeded = deepcopy(blocks, memo)
    instr = seeded[0].instrs[0]
    address = instr.args[1]
    binary = instr.args[2].args[0]
    source_shared = blocks[0].instrs[0].dst
    assert instr.dst is memo[id(source_shared)]
    assert instr.dst is address.base_values[0]
    assert instr.dst is binary.lhs
    assert instr.args[0].index is memo[id(blocks[0].instrs[0].args[0].index)]
    assert instr.args[0].index is address.base_values[1]


def test_source_and_clone_field_mutation_isolated() -> None:
    """Rebinding fields on either side never reaches the other."""
    blocks = _sample_blocks()
    memo = seed_native_copy_memo_8616(blocks)
    seeded = deepcopy(blocks, memo)
    source = blocks[0].instrs[0].dst
    clone = seeded[0].instrs[0].dst
    assert clone is memo[id(source)]
    object.__setattr__(source, "offset", 99)
    object.__setattr__(source, "expr", ("mutated",))
    object.__setattr__(source, "source_tmp", -1)
    assert clone.offset == 0
    assert clone.expr is None
    assert clone.source_tmp == 9
    object.__setattr__(clone, "name", "bx")
    object.__setattr__(clone, "memory_access_insn", -2)
    assert source.name == "ax"
    assert source.memory_access_insn == 3


def test_owned_nodes_bypass_generic_reconstruction(monkeypatch) -> None:
    """Owned node types never pay generic ``_reconstruct``; foreign data does."""
    reconstructed = []
    original = copy._reconstruct

    def observe(source, *args, **kwargs):
        reconstructed.append(type(source))
        return original(source, *args, **kwargs)

    monkeypatch.setattr(copy, "_reconstruct", observe)
    blocks = _sample_blocks()
    ordinary = deepcopy(blocks)
    assert ordinary == blocks
    ordinary_owned = sum(
        1 for item in reconstructed if item in _OWNED_NODE_TYPES
    )
    assert ordinary_owned > 0
    reconstructed.clear()
    seeded = deepcopy(blocks, seed_native_copy_memo_8616(blocks))
    assert seeded == blocks
    assert not reconstructed, (
        f"generic reconstruction survived for {set(reconstructed)}"
    )


def test_foreign_payload_still_uses_generic_reconstruction(monkeypatch) -> None:
    """An unknown payload below owned nodes keeps ordinary deepcopy."""

    class _Foreign:
        def __init__(self, tag: int) -> None:
            self.tag = tag

        def __eq__(self, other: object) -> bool:
            return type(other) is _Foreign and other.tag == self.tag

    shared_foreign = _Foreign(7)
    instr = IRInstr(
        op="X", dst=None,
        args=(cast(object, shared_foreign), cast(object, shared_foreign)),
    )
    blocks = (IRBlock(addr=1, instrs=(instr,)),)
    reconstructed = []
    original = copy._reconstruct

    def observe(source, *args, **kwargs):
        reconstructed.append(type(source))
        return original(source, *args, **kwargs)

    monkeypatch.setattr(copy, "_reconstruct", observe)
    seeded = deepcopy(blocks, seed_native_copy_memo_8616(blocks))
    assert seeded == blocks
    assert _Foreign in reconstructed
    copied_args = seeded[0].instrs[0].args
    assert copied_args[0] is copied_args[1]
    assert copied_args[0] is not shared_foreign


def test_non_leaf_and_nested_provenance_detached() -> None:
    """Values carrying index/call_output/active_unary get detached clones."""
    operand = IRValue(space=MemSpace.TMP, name="t1", size=2)
    active = IRValue(
        space=MemSpace.REG, name="cx", size=2,
        active_unary=IRActiveUnary8616(op="Iop_Not16", operand=operand, result_bits=16),
    )
    call_bound = IRValue(
        space=MemSpace.REG, name="ax", size=2,
        call_output=IRCallOutputProvenance8616(
            callsite_addr=0x10, target_addr=0x20, shape=IRCallOutputShape8616.AX,
        ),
    )
    indexed = IRValue(space=MemSpace.REG, name="dx", size=2, index=operand)
    blocks = (
        IRBlock(addr=1, instrs=(IRInstr(op="X", dst=None, args=(active, call_bound, indexed)),),),
    )
    memo = seed_native_copy_memo_8616(blocks)
    for node in (active, call_bound, indexed, operand):
        assert id(node) in memo
        assert memo[id(node)] is not node
    for provenance in (active.active_unary, call_bound.call_output):
        assert id(provenance) in memo
    seeded = deepcopy(blocks, memo)
    assert seeded == blocks
    seeded_active = seeded[0].instrs[0].args[0]
    assert seeded_active.active_unary is memo[id(active.active_unary)]
    assert seeded_active.active_unary.operand is memo[id(operand)]
    assert seeded_active.active_unary.operand is not operand


def test_subclasses_and_impostor_scalars_stay_generic() -> None:
    """Subclassed values and non-exact scalar payloads keep generic copies."""

    class _ValueSubclass(IRValue):
        pass

    class _StrSubclass(str):
        pass

    class _IntSubclass(int):
        pass

    subclassed = _ValueSubclass(space=MemSpace.REG, name="ax", size=2)
    sneaky_name = IRValue(
        space=MemSpace.REG, name=cast(str, _StrSubclass("ax")), size=2,
    )
    sneaky_offset = IRValue(
        space=MemSpace.REG, offset=cast(int, _IntSubclass(4)), size=2,
    )
    bad_expr_item = IRValue(
        space=MemSpace.REG, size=2, expr=cast(tuple[str, ...], (1,)),
    )
    list_expr = IRValue(
        space=MemSpace.REG, size=2, expr=cast(tuple[str, ...], ["a"]),
    )
    blocks = (
        IRBlock(
            addr=1,
            instrs=(
                IRInstr(
                    op="X", dst=None,
                    args=(subclassed, sneaky_name, sneaky_offset, bad_expr_item, list_expr),
                ),
            ),
        ),
    )
    memo = seed_native_copy_memo_8616(blocks)
    seeded = deepcopy(blocks, memo)
    assert seeded == blocks
    copied_args = seeded[0].instrs[0].args
    assert type(copied_args[0]) is _ValueSubclass
    assert type(copied_args[1].name) is _StrSubclass
    assert type(copied_args[2].offset) is _IntSubclass
    assert copied_args[1].name is not sneaky_name.name
    assert type(copied_args[4].expr) is list
    assert copied_args[4].expr is not list_expr.expr


def test_index_cycle_terminates_and_copy_retains_cycle() -> None:
    """Cyclic indexes resolve to the in-progress clone, keeping the cycle."""
    self_cycle = IRValue(space=MemSpace.TMP, name="t7", size=4)
    object.__setattr__(self_cycle, "index", self_cycle)
    first = IRValue(space=MemSpace.TMP, name="t8", size=4)
    second = IRValue(space=MemSpace.TMP, name="t9", size=4)
    object.__setattr__(first, "index", second)
    object.__setattr__(second, "index", first)
    blocks = (
        IRBlock(addr=1, instrs=(IRInstr(op="X", dst=None, args=(self_cycle, first, second)),),),
    )
    memo = seed_native_copy_memo_8616(blocks)
    assert id(self_cycle) in memo
    assert memo[id(self_cycle)].index is memo[id(self_cycle)]
    assert memo[id(first)].index is memo[id(second)]
    seeded = deepcopy(blocks, memo)
    copy_self, copy_first, copy_second = seeded[0].instrs[0].args
    assert copy_self.index is copy_self
    assert copy_first.index is copy_second
    assert copy_second.index is copy_first


def test_malformed_container_entries_skipped() -> None:
    """Foreign entries in the block tuple are ignored for seeding only."""
    blocks = _sample_blocks()
    payload: tuple[object, ...] = (blocks[0], "junk", None)
    memo = seed_native_copy_memo_8616(cast(tuple[IRBlock, ...], payload))
    seeded = deepcopy(payload, memo)
    assert seeded[0] == blocks[0]
    assert seeded[0] is not blocks[0]
    assert seeded[1:] == ("junk", None)
    assert seeded[0].instrs[0].dst is memo[id(blocks[0].instrs[0].dst)]


@pytest.mark.parametrize("field", ["instrs", "instruction_args", "base_values", "condition_args"])
def test_malformed_container_fields_keep_generic_copy(field):
    """Non-container payloads must not break an otherwise valid deepcopy."""
    address = IRAddress(MemSpace.DS)
    condition = IRCondition("eq", ())
    instruction = IRInstr("X", None, (address, condition))
    block = IRBlock(1, (instruction,))
    objects = {"instrs": (block, "instrs"), "instruction_args": (instruction, "args"),
               "base_values": (address, "base_values"), "condition_args": (condition, "args")}
    target, attribute = objects[field]
    object.__setattr__(target, attribute, 99)
    plain = deepcopy((block,))
    memo = seed_native_copy_memo_8616((block,))
    assert deepcopy((block,), memo) == plain
    assert memo[id(block)] is not block
