"""Require complete word-value evidence before publishing shared-return owners."""
from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CConstant, CReturn, CStatements, CVariable
from angr.sim_type import SimTypeChar, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from inertia.lowering.semantic_cast import CSemanticCast8616
from inertia.structuring.scalar_return_arm_ownership import select_scalar_return_arm_owners_8616

pytestmark = pytest.mark.decompiler


def _context():
    """Create a word-machine C AST context without running native analysis."""
    indices = count()
    return SimpleNamespace(project=SimpleNamespace(arch=Arch86_16()),
                           next_idx=lambda _kind: next(indices), next_node_idx=indices.__next__,
                           next_ident=lambda name: name)


@pytest.mark.parametrize('fault', [None, 'wide-constant', 'truncated-word'])
def test_return_arm_selection_requires_full_word_value(fault):
    """Equal low bytes or a shared storage slot cannot prove a native word return."""
    cg = _context()
    word = SimTypeShort(True).with_arch(cg.project.arch)
    byte = SimTypeChar(False).with_arch(cg.project.arch)
    first = CConstant(0,word,codegen=cg)
    native_first = first
    if fault == 'wide-constant':
        first = CConstant(0x10000,SimTypeLong(False).with_arch(cg.project.arch),codegen=cg)
    elif fault == 'truncated-word':
        value = CVariable(SimStackVariable(4,2,base='bp'),variable_type=word,codegen=cg)
        native_first = CSemanticCast8616(word,word,CSemanticCast8616(word,word,value,codegen=cg),codegen=cg)
        truncated = CSemanticCast8616(word,byte,value,codegen=cg)
        first = CSemanticCast8616(byte,word,truncated,codegen=cg)

    def body(expr):
        return CStatements([CReturn(expr,codegen=cg,tags={'vex_block_addr':0x9000})],codegen=cg)

    one,two = CConstant(1,word,codegen=cg),CConstant(2,word,codegen=cg)
    argument = IRValue(MemSpace.SS,name='bp',offset=6,size=2)
    facts = (
        ConditionIR('eq',argument,IRValue(MemSpace.CONST,const=0,size=2),
                    src_insn=0x1012,block_addr=0x1010,taken_target=0x1100,fallthrough_target=0x1020),
        ConditionIR('eq',argument,IRValue(MemSpace.CONST,const=1,size=2),
                    src_insn=0x1022,block_addr=0x1020,taken_target=0x1200,fallthrough_target=0x1210),
    )
    native = {0x1100:native_first,0x1200:one,0x1210:two}
    result = select_scalar_return_arm_owners_8616(
        (body(first),body(one)),body(two),facts,
        successors={0x1010:(0x1100,0x1020),0x1020:(0x1200,0x1210)},
        recover_return=native.get,
    )
    assert result.selected is (fault is None)
