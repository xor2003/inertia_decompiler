"""VEX address identity must remain available after typed import and SSA."""

import pickle
from dataclasses import replace

import pyvex
from angr_platforms.X86_16.ir.instruction_origin import IRInstructionOrigin8616, vex_instruction_origin_8616
from angr_platforms.X86_16.ir.ssa import build_x86_16_block_local_ssa
from angr_platforms.X86_16.ir.ssa_memory import build_x86_16_function_memory_ssa
from angr_platforms.X86_16.semantics.call_stack_effects import materialize_call_stack_effects_8616
from test_x86_16_call_stack_effects import _artifact, _summary
from test_x86_16_segment_stack_restore import _lift_function


def test_segmented_load_retains_exact_address_temporary():
    artifact = _lift_function(bytes.fromhex("8e c2 26 8b 07 c3"))
    block = artifact.blocks[0]
    definitions = {item.dst.source_tmp: item for item in block.instrs if item.dst is not None}
    loads = [item for item in block.instrs if item.op == "LOAD" and item.addr == 0x1002]
    assert len(loads) == 2
    for load in loads:
        assert load.origin is not None
        assert load.origin.block_addr == block.addr
        address = definitions[load.origin.address_tmp]
        assert address.op == "Iop_Add32"
        assert address.origin is not None
        assert address.origin.statement_index < load.origin.statement_index
        assert address.addr == load.addr


def test_ssa_and_persistence_preserve_instruction_origin():
    block = _lift_function(bytes.fromhex("8e c2 26 8b 07 c3")).blocks[0]
    ssa = build_x86_16_block_local_ssa(block)
    assert any(item.origin is not None for item in block.instrs)
    assert [item.origin for item in ssa.instrs] == [item.origin for item in block.instrs]
    memory = build_x86_16_function_memory_ssa(block.addr, (ssa,), {block.addr: ()})
    assert [item.origin for item in memory.blocks[0].instrs] == [item.origin for item in block.instrs]
    restored = pickle.loads(pickle.dumps(block))
    assert restored == block
    for original, decoded in zip(block.instrs, restored.instrs, strict=True):
        assert original.to_dict()["origin"] == decoded.to_dict()["origin"]


def test_synthetic_terminal_does_not_claim_a_vex_statement():
    block = _lift_function(bytes.fromhex("8e c2 26 8b 07 c3")).blocks[0]
    assert block.instrs[-1].op == "RET"
    assert block.instrs[-1].origin is None


def test_ssa_cache_does_not_reuse_another_source_origin():
    block = _lift_function(bytes.fromhex("8e c2 26 8b 07 c3")).blocks[0]
    previous = build_x86_16_block_local_ssa(block)
    first, *rest = block.instrs
    new_origin = IRInstructionOrigin8616(0x2000, 123)
    changed = replace(block, instrs=(replace(first, origin=new_origin), *rest))
    current = build_x86_16_block_local_ssa(changed)
    assert current.instrs[0].origin == new_origin
    assert previous.instrs[0].origin != new_origin


def test_store_origin_captures_only_an_explicit_address_temporary():
    value = pyvex.expr.Const(pyvex.const.U8(1))
    temporary = pyvex.stmt.Store(pyvex.expr.RdTmp(7), value, "Iend_LE")
    literal = pyvex.stmt.Store(pyvex.expr.Const(pyvex.const.U32(7)), value, "Iend_LE")
    assert vex_instruction_origin_8616(temporary, block_addr=0x1000, statement_index=2).address_tmp == 7
    assert vex_instruction_origin_8616(literal, block_addr=0x1000, statement_index=2).address_tmp is None


def test_call_effect_enrichment_preserves_source_identity():
    artifact = _artifact()
    block = artifact.blocks[0]
    instructions = tuple(replace(item, origin=IRInstructionOrigin8616(block.addr, index))
                         for index, item in enumerate(block.instrs))
    source = replace(artifact, blocks=(replace(block, instrs=instructions),))
    enriched = materialize_call_stack_effects_8616(source, {0x1003: _summary()})
    assert enriched.complete
    assert [item.origin for item in enriched.function.blocks[0].instrs] == [item.origin for item in instructions]
