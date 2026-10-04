"""Near returns retain architectural offsets and full loaded destinations."""
from pathlib import Path

import pytest
import z3
from test_dosunit_tool import _mz_exe
from test_real16_region_proof import _document

from tools.dosunit import straightline_ssa as S
from tools.dosunit.real16_call_contracts import initial_state, materialize_function
from tools.dosunit.real16_call_evidence import group_lookup
from tools.dosunit.real16_mz_load import image_from_mz_bytes
from tools.dosunit.real16_replay import replay
from tools.dosunit.real16_replay_model import CallerFrame, FrameKind, Real16ReplayStatus, Real16Vector, SegOffset


@pytest.mark.parametrize("code,cleanup", [(bytes.fromhex("c3"),0),(bytes.fromhex("c20200"),2)])
def test_near_return_loaded_destination_matches_guest(tmp_path: Path, code: bytes, cleanup: int) -> None:
    """A legal high physical caller destination must survive the frontend PC."""
    doc = _document(tmp_path,code,"return-coordinate")
    _, ctx = group_lookup(doc,"demo.exe:loop")
    state=S._compose_block_outputs(ctx.blocks[0],ctx.blocks[0]["outputs"],initial_state())
    document=materialize_function("return:effect",state)
    inputs=S._z3_inputs(document,document,z3)
    assignments={item["id"]:item for item in document["assignments"]}
    control=S._z3_term(document["outputs"]["control_ip"],document=document,inputs=inputs,z3=z3,assignments=assignments,cache={})
    target=SegOffset(0x66,0xfbc0)
    entry=SegOffset(target.segment,ctx.entry_linear-target.segment*16)
    data=bytearray(0x300)
    data[0x200:0x200+len(code)]=code
    image=image_from_mz_bytes(_mz_exe(bytes(data)), load_segment=0x100)
    vector=Real16Vector((("sp",0xbffe),("flags",2)),(("ss",0x7000),("ds",0x100),("es",0x100)),CallerFrame(FrameKind.NEAR16,target))
    guest=replay(image,entry,vector)
    assert guest.status is Real16ReplayStatus.RETURNED,guest
    regs=dict(guest.registers)
    assert regs["cs"]*16+regs["ip"]==target.linear()==0x10220
    assert regs["sp"]==0xc000+cleanup
    solver=z3.Solver()
    solver.add(inputs["cs"][0]==target.segment,inputs["ss"][0]==0x7000,inputs["sp"][0]==0xbffe)
    memory=inputs["mem"][0]
    for byte,value in enumerate(target.offset.to_bytes(2,"little")):
        solver.add(z3.Select(memory,z3.BitVecVal(0x7000*16+0xbffe+byte,32))==value)
    solver.add(control!=target.linear())
    checked=solver.check()
    assert checked==z3.unsat,(checked,solver.model() if checked==z3.sat else solver.reason_unknown())
