"""Consumed call arguments must not erase storage still read by POP projections."""
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CConstant, CVariable
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable
from capstone.x86_const import X86_INS_PUSH

from inertia.lowering.real_mode_linear import prune_consumed_call_push_stack_assignments_8616
from tests.lowering.test_x86_16_segmented_runtime_lowering import _project, _reg

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize('read_offset, expected_removed', [(-4, False), (-3, False), (-8, True), (None, True), ('self', False)])
def test_consumed_push_preserves_later_stack_read(read_offset, expected_removed):
    project, codegen = _project()
    local = CVariable(SimStackVariable(-4, 2, base='bp', region=0x4010),
                      variable_type=SimTypeShort(False), codegen=codegen)
    value = CConstant(3, SimTypeShort(False), codegen=codegen)
    store = CAssignment(local, value, codegen=codegen, tags={'ins_addr': 0x4016})
    codegen.cfunc.statements.statements.append(store)
    if read_offset == 'self':
        store.rhs = local
    elif read_offset is not None:
        read = CVariable(SimStackVariable(read_offset, 1, base='bp', region=0x4010),
                         variable_type=SimTypeChar(False), codegen=codegen)
        codegen.cfunc.statements.statements.append(CAssignment(_reg(project,'cx',codegen), read,
                                                               codegen=codegen, tags={'ins_addr':0x401a}))
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(addr=0x4010,
        capstone=SimpleNamespace(insns=(SimpleNamespace(address=0x4016,id=X86_INS_PUSH),))),))
    changed = prune_consumed_call_push_stack_assignments_8616(project, codegen, frozenset({0x4016}),
        materialized_args_by_push_instruction_addr={0x4016:(value,)}, function=function)
    assert changed is expected_removed
    assert (store not in codegen.cfunc.statements.statements) is expected_removed
