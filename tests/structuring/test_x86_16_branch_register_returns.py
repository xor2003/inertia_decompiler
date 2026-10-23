"""Require exact native register authority for word return copies."""
from types import SimpleNamespace

import pytest
from capstone import CS_ARCH_X86, CS_MODE_16, Cs

from inertia.cli.project_loading import _build_project_from_bytes
from inertia.ir.core import MemSpace
from inertia.semantics.branch_target_return import branch_target_return_effect_8616
from inertia.semantics.return_effect_operands import BranchTargetReturnEffectKind8616
from inertia.structuring.branch_return_expressions import branch_return_register_source_8616
from inertia.structuring.return_chains import (
    BranchTargetReturnRegisterState8616,
    BranchTargetReturnScanCallbacks8616,
    scan_branch_target_return_block_8616,
)


def _block(hexbytes, address=0x1000):
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    return SimpleNamespace(capstone=SimpleNamespace(insns=tuple(decoder.disasm(bytes.fromhex(hexbytes), address))))


def _callbacks(source=None):
    return BranchTargetReturnScanCallbacks8616(
        branch_target_imm=lambda instruction: instruction.operands[0].imm,
        combine_return_expr=lambda ax, dx: ax if dx is None else (ax, dx),
        materialize_reg_imm=lambda value: value,
        materialize_stack_load=lambda offset, size: (offset, size),
        materialize_direct_global_load=lambda offset, size: None,
        materialize_ax_alu_imm=lambda value, operation, immediate: None,
        materialize_ax_incdec=lambda value, operation: None,
        materialize_reg_copy=source,
    )


@pytest.mark.parametrize('code, register', [('8bc2c3', 'dx'), ('8bc3c3', 'bx')])
def test_word_copy_needs_exact_instruction_source_and_does_not_seed_high_half(code, register):
    seen = []
    def source(address, name):
        seen.append((address, name))
        return 7
    state = BranchTargetReturnRegisterState8616()
    result = scan_branch_target_return_block_8616(_block(code), _callbacks(source), register_state=state)
    assert result.expr == 7
    assert state.dx_value is None
    assert seen == [(0x1000, register)]
    assert scan_branch_target_return_block_8616(_block(code), _callbacks()).expr is None


@pytest.mark.parametrize('code', ['88d0c3', '668bc2c3', 'c70700008bc3c3', 'e800008bc3c3'])
def test_partial_wide_memory_and_call_paths_refuse(code):
    result = scan_branch_target_return_block_8616(_block(code), _callbacks(lambda address, register: 7))
    assert result.expr is None


def test_source_pop_clobber_survives_jump_block_boundary():
    state = BranchTargetReturnRegisterState8616()
    callbacks = _callbacks(lambda address, register: 7)
    first = scan_branch_target_return_block_8616(_block('5beb00'), callbacks, register_state=state)
    assert first.next_target == 0x1003
    assert scan_branch_target_return_block_8616(_block('8bc3c3', 0x1003), callbacks, register_state=state).expr is None


@pytest.mark.parametrize('load, prefix, valid', [('8b5604', '', True), ('8a5604', '', False), ('8b5604', 'e80000', False), ('8b5604', '894604', False)])
def test_copy_authority_uses_retained_whole_function_current_source(load, prefix, valid):
    code = bytes.fromhex('558bec' + load + prefix + '8bc25dc3')
    project = _build_project_from_bytes(code, base_addr=0x1000, entry_point=0x1000)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]
    codegen = SimpleNamespace(_func=function, cfunc=SimpleNamespace(addr=0x1000))
    address = 0x1000 + 3 + len(bytes.fromhex(load + prefix))
    value = branch_return_register_source_8616(project, codegen, address, 'dx')
    if valid:
        assert value is not None
        assert (value.space, value.name, value.offset, value.size) == (MemSpace.SS, 'bp', 4, 2)
    else:
        assert value is None
    assert branch_return_register_source_8616(project, SimpleNamespace(), address, 'dx') is None


def test_semantic_copy_carries_full_word_source_register():
    instruction = _block('8bc3').capstone.insns[0]
    effect = branch_target_return_effect_8616(instruction, lambda insn: None)
    assert effect.kind is BranchTargetReturnEffectKind8616.MOV_REG_REG
    assert (effect.dst_reg, effect.src_reg) == ('ax', 'bx')


def test_both_actual_comparison_arms_use_function_scoped_stack_sources():
    code = bytes.fromhex('558bec8b56048b5e063bd377048bc2eb048bc3ebfa5dc3')
    project = _build_project_from_bytes(code, base_addr=0x1000, entry_point=0x1000)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    codegen = SimpleNamespace(_func=cfg.kb.functions[0x1000], cfunc=SimpleNamespace(addr=0x1000))
    for address, register, offset in [(0x100d, 'dx', 4), (0x1011, 'bx', 6)]:
        source = branch_return_register_source_8616(project, codegen, address, register)
        assert source is not None
        assert (source.space, source.name, source.offset, source.size) == (MemSpace.SS, 'bp', offset, 2)
    assert branch_return_register_source_8616(project, codegen, 0x100e, 'dx') is None
