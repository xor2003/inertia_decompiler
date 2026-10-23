"""Source-IR proof of numeric frame values after real call transfers."""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.alias.numeric_stack_pointer_values import prove_numeric_stack_pointer_assignment_8616
from inertia.ir.core import IRBlock, IRInstr, IRValue, MemSpace
from inertia.semantics.call_stack_effects import materialize_call_stack_effects_8616
from inertia.semantics.numeric_stack_pointer_returns import (
    NumericStackPointerReturnRefusal8616,
    apply_numeric_stack_pointer_return_inventory_8616,
    build_numeric_stack_pointer_return_inventory_8616,
    numeric_stack_pointer_return_inventory_8616,
    prove_numeric_stack_pointer_return_8616,
)
from inertia.semantics.register_definition_return import unchanged_register_return_path_8616
from tests.semantics.test_call_stack_coordinates import _world


def _fixture():
    """Keep the real call, stack adjustment, and AX := SP definition."""
    project, _, source, summary = _world(
        bytes.fromhex("55 89e5 50 e80900 83c402 89e0 89ec 5d c3 c3"), 0x1004,
    )
    artifact = materialize_call_stack_effects_8616(
        source, {0x1004: summary}, project=project,
    ).function
    block = next(block for block in artifact.blocks if block.addr == 0x1007)
    index = next(
        index for index, instruction in enumerate(block.instrs)
        if instruction.addr == 0x100a and instruction.dst is not None
        and instruction.dst.space is MemSpace.REG and instruction.dst.name == "ax"
    )
    return source, artifact, block, index


def test_real_call_numeric_sp_is_an_entry_value_coordinate():
    """An accepted call and ADD SP,2 leave the captured word at entry SP-2."""
    _, artifact, block, index = _fixture()
    fact = prove_numeric_stack_pointer_assignment_8616(artifact, block.addr, index)
    assert fact is not None
    assert (fact.register, fact.entry_sp_offset, fact.width_bits) == ("ax", -2, 16)
    assert fact.instruction_addr == 0x100a


def test_same_block_numeric_value_owns_exact_return():
    """The source AX definition survives epilogue effects to the actual RET."""
    _, artifact, block, _ = _fixture()
    fact = prove_numeric_stack_pointer_return_8616(artifact, block.addr, 0x100f)
    assert fact is not None
    assert fact.assignment.entry_sp_offset == -2
    assert fact.path.definition_addr == 0x100a
    assert fact.path.return_addr == 0x100f


@pytest.mark.parametrize("return_addr", [0x1007, 0x100a, 0x1010])
def test_expression_origin_cannot_stand_in_for_actual_ret(return_addr):
    """A folded ADD or another function's RET cannot own this return use."""
    _, artifact, block, _ = _fixture()
    assert prove_numeric_stack_pointer_return_8616(artifact, block.addr, return_addr) is None


def test_later_partial_register_write_refuses_numeric_return():
    """A proven old AX scalar cannot survive an unproved AL overwrite."""
    _, artifact, block, index = _fixture()
    original = block.instrs[index]
    overwrite = replace(original, addr=0x100b, dst=replace(original.dst, name="al", size=1))
    altered = replace(block, instrs=(*block.instrs[:-1], overwrite, block.instrs[-1]))
    mutated = replace(artifact, blocks=tuple(altered if item.addr == block.addr else item for item in artifact.blocks))
    assert prove_numeric_stack_pointer_return_8616(mutated, block.addr, 0x100f) is None


def test_numeric_return_inventory_accounts_for_published_proofs():
    """Source proof publication closes its ledger without claiming C lowering."""
    _, artifact, _, _ = _fixture()
    inventory = build_numeric_stack_pointer_return_inventory_8616(artifact)
    assert inventory.source_ir is artifact
    stats = inventory.stats
    assert (stats.raw_fact_count, stats.normalized_fact_count) == (1, 1)
    assert (stats.classified_fact_count, stats.materialized_count, stats.failure_count) == (1, 1, 0)
    assert stats.refusal_count == 0
    assert inventory.observations[0].proof is not None


def test_numeric_return_inventory_retains_unknown_call_refusal():
    """An unknown scalar remains a typed recorded outcome, never a zero value."""
    source, _, _, _ = _fixture()
    inventory = build_numeric_stack_pointer_return_inventory_8616(source)
    assert inventory.stats.classified_fact_count == inventory.stats.materialized_count == 0
    assert inventory.stats.raw_fact_count == inventory.stats.refusal_count == 1
    assert inventory.observations[0].refusal is NumericStackPointerReturnRefusal8616.UNKNOWN_VALUE_OR_PATH


def test_numeric_return_publication_does_not_survive_ir_replacement():
    """An installed artifact from another source projection cannot feed Types."""
    source, artifact, _, _ = _fixture()
    boundary = SimpleNamespace(_inertia_vex_ir_artifact=artifact)
    inventory = apply_numeric_stack_pointer_return_inventory_8616(boundary)
    assert numeric_stack_pointer_return_inventory_8616(boundary) is inventory
    boundary._inertia_vex_ir_artifact = source
    assert numeric_stack_pointer_return_inventory_8616(boundary) is None


def test_preserved_path_does_not_authorize_shared_epilogue_owner():
    """Another predecessor can supply a different AX at the same source RET."""
    _, artifact, block, _ = _fixture()
    terminal = block.instrs[-1]
    selected = replace(block, instrs=block.instrs[:-1], successor_addrs=(0x100f,))
    alternative = IRBlock(
        addr=0x2000,
        instrs=(IRInstr(
            op="MOV", addr=0x2000,
            dst=IRValue(space=MemSpace.REG, name="ax", size=2),
            args=(IRValue(space=MemSpace.CONST, const=42, size=2),),
        ),),
        successor_addrs=(0x100f,),
    )
    entry = artifact.blocks[0]
    entry = replace(entry, successor_addrs=(*entry.successor_addrs, alternative.addr))
    shared = IRBlock(addr=0x100f, instrs=(terminal,))
    mutated = replace(artifact, blocks=(entry, selected, alternative, shared))
    path = unchanged_register_return_path_8616(mutated, 0x100a, "ax")
    assert path is not None and path.return_addr == 0x100f
    assert prove_numeric_stack_pointer_return_8616(mutated, shared.addr, 0x100f) is None


def test_unknown_call_does_not_authorize_numeric_entry_sp():
    """Raw CALL without accepted transfer evidence cannot prove a coordinate."""
    source, _, block, index = _fixture()
    assert prove_numeric_stack_pointer_assignment_8616(source, block.addr, index) is None


@pytest.mark.parametrize("change", [{"size": 1}, {"offset": 1}, {"version": 3}, {"source_tmp": 999}])
def test_mutated_capture_view_refuses(change):
    """An old temporary ID alone does not earn a different operand view."""
    _, artifact, block, index = _fixture()
    instruction = block.instrs[index]
    changed = replace(instruction, args=(replace(instruction.args[0], **change),))
    new_block = replace(block, instrs=(*block.instrs[:index], changed, *block.instrs[index + 1:]))
    mutated = replace(artifact, blocks=tuple(new_block if item.addr == block.addr else item for item in artifact.blocks))
    assert prove_numeric_stack_pointer_assignment_8616(mutated, block.addr, index) is None


def test_duplicate_block_scope_refuses():
    """A dictionary projection must not silently hide competing block owners."""
    _, artifact, block, index = _fixture()
    duplicated = replace(artifact, blocks=(*artifact.blocks, block))
    assert prove_numeric_stack_pointer_assignment_8616(duplicated, block.addr, index) is None


def test_missing_cfg_edge_scope_refuses():
    """Incomplete predecessor coverage cannot earn an entry coordinate."""
    _, artifact, block, index = _fixture()
    altered = replace(block, successor_addrs=(*block.successor_addrs, 0x9000))
    incomplete = replace(artifact, blocks=tuple(altered if item.addr == block.addr else item for item in artifact.blocks))
    assert prove_numeric_stack_pointer_assignment_8616(incomplete, block.addr, index) is None


@pytest.mark.parametrize("change", [{"size": 1}, {"offset": 1}, {"version": 3}, {"memory_access_size": 2}])
def test_mutated_capture_definition_refuses(change):
    """The defining TMP must earn the exact scalar, not just reuse its ID."""
    _, artifact, block, index = _fixture()
    tmp = block.instrs[index].args[0].source_tmp
    producer_index = next(
        position for position, instruction in enumerate(block.instrs)
        if instruction.dst is not None and instruction.dst.space is MemSpace.TMP
        and instruction.dst.source_tmp == tmp
    )
    producer = block.instrs[producer_index]
    altered = replace(producer, dst=replace(producer.dst, **change))
    new_block = replace(block, instrs=(*block.instrs[:producer_index], altered, *block.instrs[producer_index + 1:]))
    mutated = replace(artifact, blocks=tuple(new_block if item.addr == block.addr else item for item in artifact.blocks))
    assert prove_numeric_stack_pointer_assignment_8616(mutated, block.addr, index) is None
