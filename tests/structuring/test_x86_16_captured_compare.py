"""Layer: Structuring tests.
Responsibility: preserve Alias-proven captured CALL values during condition decoding.
"""
from types import SimpleNamespace

import capstone
import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CConstant, CFunctionCall, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import IRValue, MemSpace
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.postprocess import decompiler_postprocess_jcc as owner
from inertia.structuring.condition_lowering import materialize_reaching_register_projection_8616
from tests.structuring.test_x86_16_condition_lowering import (
    REACH_BLOCK,
    REACH_CALLSITE,
    REACH_FUNC_ADDR,
    _install_reach_inventory,
    _reach_codegen,
    _reach_condition,
    _temporary,
    _word_insert_assignment,
)

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize('clobber', [False, True])
def test_cmp_uses_captured_call_value_or_refuses(monkeypatch: pytest.MonkeyPatch, clobber: bool) -> None:
    """Alias-backed capture survives flags; an intervening AX definition refuses reuse."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    captured = _temporary(codegen)
    call = CFunctionCall('callee', SimpleNamespace(addr=0x3000, name='callee'), [], codegen=codegen,
                         tags={'ins_addr': REACH_CALLSITE})
    capture = CAssignment(captured, call, codegen=codegen, tags={'ins_addr': REACH_CALLSITE})
    assignment = _word_insert_assignment(codegen, captured, ins_addr=REACH_CALLSITE, block_addr=REACH_FUNC_ADDR)
    flags = CAssignment(CVariable(SimRegisterVariable(32, 2), codegen=codegen),
                        CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen,
                        tags={'ins_addr': REACH_BLOCK})
    codegen.cfunc.statements = CStatements((capture, assignment, flags), codegen=codegen)
    prefix = bytes.fromhex('b83412' if clobber else '83c406')
    _install_reach_inventory(monkeypatch, project, codegen, (
        (REACH_FUNC_ADDR, (), bytes.fromhex('e80000')),
        (REACH_BLOCK, (REACH_FUNC_ADDR,), prefix + bytes.fromhex('3d81037405')),
    ))
    condition = _reach_condition(producer=REACH_BLOCK + 3)
    projection = materialize_reaching_register_projection_8616(
        IRValue(MemSpace.REG, name='ax', size=2), condition, project, codegen)
    assert (projection.expression is None) is clobber
    if not clobber:
        assert projection.expression is captured
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    engine.detail = True
    compare, branch = tuple(engine.disasm(bytes.fromhex('3d81037405'), REACH_BLOCK + 3))
    invented = CFunctionCall('callee', SimpleNamespace(addr=0x3000, name='callee'), [], codegen=codegen)
    monkeypatch.setattr(owner, '_call_return_expr_before_insn_8616', lambda *_args: invented)
    monkeypatch.setattr(owner, '_lookup_prior_register_stack_load_8616', lambda *_args: None)
    registers = {} if clobber else {(compare.address, 'ax', 2): projection.expression}
    result = owner._decode_cmp_operands_guard_8616(
        project, codegen, REACH_BLOCK, branch.address, 'je', (compare, branch), 1,
        compare, registers, None, False)
    if clobber:
        assert result is None
    else:
        assert result is not None and result.lhs is captured
        assert not any(isinstance(node, CFunctionCall) for node in _iter_c_nodes_deep_8616(result.lhs))
    assert sum(isinstance(node, CFunctionCall) for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements)) == 1
