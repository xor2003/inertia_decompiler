"""Preserve incoming register bits across partial writes and CFG joins."""

import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import IRInstr, IRValue, MemSpace
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.lowering.gp_register_state import gp_live_in_names_from_ssa_8616


def register(name):
    offset, size = Arch86_16().registers[name]
    return IRValue(MemSpace.REG, name=name, offset=offset, size=size)


def write(name):
    value = register(name)
    return IRInstr("MOV", value, (IRValue(MemSpace.CONST, const=0, size=value.size),), value.size, 0x100)


def read(name):
    value = register(name)
    return IRInstr("MOV", IRValue(MemSpace.TMP, name="t0", size=value.size), (value,), value.size, 0x102)


@pytest.mark.parametrize("writes,reader,expected", [
    (("al",), "ah", {"eax"}),
    (("al",), "ax", {"eax"}),
    (("ax",), "eax", {"eax"}),
    (("si",), "esi", {"esi"}),
    (("al", "ah"), "ax", set()),
    (("eax",), "ah", set()),
    (("si",), "si", set()),
])
def test_partial_definition_preserves_unwritten_live_in(writes, reader, expected):
    block = SSABlock(addr=0x100, instrs=(*(write(name) for name in writes), read(reader)), bindings=())
    artifact = SSAFunctionArtifact(function_addr=0x100, blocks=(block,), predecessor_map={0x100: ()})
    assert gp_live_in_names_from_ssa_8616(artifact) == frozenset(expected)


def test_join_requires_same_bits_defined_on_every_path():
    blocks = (
        SSABlock(addr=0x100, instrs=(), bindings=()),
        SSABlock(addr=0x110, instrs=(write("al"),), bindings=()),
        SSABlock(addr=0x120, instrs=(write("ah"),), bindings=()),
        SSABlock(addr=0x130, instrs=(read("ax"),), bindings=()),
    )
    artifact = SSAFunctionArtifact(function_addr=0x100, blocks=blocks,
        predecessor_map={0x100: (), 0x110: (0x100,), 0x120: (0x100,), 0x130: (0x110, 0x120)})
    assert gp_live_in_names_from_ssa_8616(artifact) == frozenset({"eax"})
