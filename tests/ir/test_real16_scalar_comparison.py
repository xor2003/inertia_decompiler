"""Known scalar comparisons reuse the canonical bitvector comparison owner."""
import pytest

from inertia.ir import real16_invocation_domain as owner


@pytest.mark.parametrize('op,left,right,expected',[
    ('Iop_CmpNE16',0,0,0),('Iop_CmpNE16',5,0,1),
    ('Iop_CmpEQ16',0x10000,0,1),('Iop_CmpEQ1',2,0,1),
    ('Iop_CmpLT16S',0xffff,0,1),('Iop_CmpLT16U',0xffff,0,0),
    ('Iop_CmpGE32S',0x80000000,0,0),('Iop_CmpGE32U',0x80000000,0,1),
    ('Iop_CmpLE64S',0xffffffffffffffff,0,1),
    ('Iop_CmpGT8U',0xff,1,1),('Iop_CmpEQ17',1,1,None),
])
def test_known_compare_uses_declared_width_and_signedness(op,left,right,expected):
    assert owner._eval_binary_op_8616(op,left,right) == expected

@pytest.mark.parametrize('known',[False,True])
def test_comparison_tmp_never_invents_unknown_operand(known):
    dst=owner.IRValue(space=owner.MemSpace.TMP,name='t7',size=1,source_tmp=7)
    left=owner.IRValue(space=owner.MemSpace.REG,name='ax',size=2)
    right=owner.IRValue(space=owner.MemSpace.CONST,const=0,size=2)
    row=owner.IRInstr(op='Iop_CmpNE16',dst=dst,args=(left,right),size=1,addr=0x10000)
    temps={7:99}
    owner._simulate_tmp_write_8616(row,dst,{'ax':5} if known else {},temps)
    assert temps == ({7:1} if known else {})
