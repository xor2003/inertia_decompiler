"""Wide call condition polarity must be proven before scalar C exists."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir.core import IRInstr, IRRefusal
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.structuring.wide_call_condition_plan import plan_wide_call_condition_8616
from test_x86_16_call_output_stack_objects import _wide_condition_fixture


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("damage", [None, "missing_edge", "wrong_low_exit", "same_exit"])
def test_typed_wide_call_cfg_plan_requires_complete_ordering(reverse, damage):
    _codegen, _expression, conditions, _call, _wide = _wide_condition_fixture()
    high, equal, low = conditions
    repeat, exit_address = 0x1020, 0x1030
    chain = (
        replace(high, block_addr=high.src_insn, taken_target=equal.src_insn, fallthrough_target=exit_address),
        replace(equal, block_addr=equal.src_insn, taken_target=low.src_insn, fallthrough_target=repeat),
        replace(low, block_addr=low.src_insn, taken_target=repeat, fallthrough_target=exit_address),
    )
    if damage == "wrong_low_exit":
        chain = (*chain[:2], replace(chain[2], taken_target=exit_address))
    successors = {condition.block_addr: (condition.taken_target, condition.fallthrough_target) for condition in chain}
    if damage == "missing_edge":
        successors[chain[0].block_addr] = ()
    true_target, false_target = (exit_address, repeat) if reverse else (repeat, exit_address)
    if damage == "same_exit":
        false_target = true_target

    result = plan_wide_call_condition_8616(
        chain[0], {condition.block_addr: condition for condition in chain},
        successors, true_target, false_target,
    )

    if damage is not None:
        assert result is None
    else:
        assert result is not None
        assert result.operator == ("sgt" if reverse else "sle")
        assert result.conditions == chain


@pytest.mark.parametrize("damage", [None, "effect", "refusal", "missing", "mismatch", "cycle"])
def test_wide_plan_requires_ssa_proof_for_every_intermediate_jump(damage):
    _, _, conditions, _, _ = _wide_condition_fixture()
    high, equal, low = conditions
    repeat, exit_address, first, second = 0x1020, 0x1030, 0x1040, 0x1050
    chain = (
        replace(high, block_addr=high.src_insn, taken_target=equal.src_insn, fallthrough_target=exit_address),
        replace(equal, block_addr=equal.src_insn, taken_target=low.src_insn, fallthrough_target=first),
        replace(low, block_addr=low.src_insn, taken_target=repeat, fallthrough_target=exit_address),
    )
    edges = {c.block_addr: (c.taken_target, c.fallthrough_target) for c in chain}
    edges.update({first: (second,), second: (repeat,)})
    artifact = SSAFunctionArtifact(
        high.src_insn, (SSABlock(first, (), ()), SSABlock(second, (), ())),
        predecessor_map={second: (first,), repeat: (second,)},
    )
    if damage == "effect":
        instruction = IRInstr(op="CALL", dst=None, args=(), size=0, addr=second)
        artifact = replace(artifact, blocks=(artifact.blocks[0], SSABlock(second, (instruction,), ())))
    elif damage == "refusal":
        artifact = replace(artifact, memory_refusals=(IRRefusal("unknown", "missing effects", second),))
    elif damage == "missing":
        artifact = None
    elif damage == "mismatch":
        artifact = replace(artifact, predecessor_map={})
    elif damage == "cycle":
        edges[second] = (first,)
        artifact = replace(artifact, predecessor_map={second: (first,), first: (second,)})
    result = plan_wide_call_condition_8616(
        chain[0], {c.block_addr: c for c in chain}, edges, repeat, exit_address, artifact=artifact,
    )
    if damage is None:
        assert result is not None
        assert result.operator == "sle"
        assert result.conditions == chain
    else:
        assert result is None
