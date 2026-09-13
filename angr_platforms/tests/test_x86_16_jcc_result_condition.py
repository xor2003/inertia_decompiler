"""Direct zero branches must use the just-written register result."""

from types import SimpleNamespace

import pytest
import pyvex
from angr_platforms.X86_16 import lift_86_16
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lift_86_16 import Instruction_ANY
from test_x86_16_lift_condition import _FakeInstruction


def _instruction(semantics, *, adjacent=True):
    values = _FakeInstruction()
    return SimpleNamespace(
        addr=0x2003,
        _past_instructions=[SimpleNamespace(
            addr=0x2000, cs=SimpleNamespace(size=3 if adjacent else 2),
            simple_semantics=semantics, emu=None,
        )],
        _cmp_operands_from_semantics=lambda _semantics: None,
        constant=values.constant, get=values.get,
    )


@pytest.mark.parametrize("semantics", [
    ("sub_reg_imm16", "ax", 27), ("add_reg_imm16", "bx", 1),
    ("dec_reg16", "ax"), ("inc_reg16", "cx"),
])
@pytest.mark.parametrize(("kind", "operator"), [("je", "=="), ("jz", "=="), ("jne", "!="), ("jnz", "!=")])
def test_result_zero_jcc_uses_current_result(semantics, kind, operator):
    result = Instruction_ANY._direct_jcc_condition(_instruction(semantics), kind)
    assert repr(result) == f"({semantics[1]} {operator} 0)"


@pytest.mark.parametrize("kind", ["jb", "ja", "jl", "jge", "jo", "js", "jp"])
def test_result_zero_jcc_does_not_replace_other_flags(kind):
    assert Instruction_ANY._direct_jcc_condition(_instruction(("dec_reg16", "ax")), kind) is None


def test_result_zero_jcc_requires_adjacent_producer():
    assert Instruction_ANY._direct_jcc_condition(_instruction(("dec_reg16", "ax"), adjacent=False), "je") is None


@pytest.mark.parametrize("semantics", [
    ("cmp_reg_imm16", "ax", 1), ("shl_reg_imm16", "ax", 0),
    ("dec_reg16", "eax"), ("dec_reg16", "flags"), ("dec_reg16",),
])
def test_result_zero_jcc_refuses_unproven_producers(semantics):
    assert Instruction_ANY._direct_jcc_condition(_instruction(semantics), "je") is None


def _guard_reads(block):
    definitions = {stmt.tmp: stmt.data for stmt in block.statements if isinstance(stmt, pyvex.stmt.WrTmp)}
    pending = [stmt.guard for stmt in block.statements if isinstance(stmt, pyvex.stmt.Exit)]
    reads = set()
    visited = set()
    while pending:
        expr = pending.pop()
        if id(expr) in visited:
            continue
        visited.add(id(expr))
        if isinstance(expr, pyvex.expr.Get):
            reads.add(expr.offset)
        elif isinstance(expr, pyvex.expr.RdTmp):
            pending.append(definitions[expr.tmp])
        else:
            pending.extend(expr.child_expressions)
    return reads


@pytest.mark.parametrize("arithmetic", ["83e81b", "83c001", "40", "48"])
def test_real_lift_uses_result_without_removing_flag_writes(arithmetic, monkeypatch):
    arch = Arch86_16()
    code = bytes.fromhex(arithmetic + "75029090")
    result_block = pyvex.IRSB(code, 0x1000, arch, opt_level=0)
    flags_offset = arch.registers["flags"][0]
    assert _guard_reads(result_block) == {arch.registers["ax"][0]}
    assert any(isinstance(stmt, pyvex.stmt.Put) and stmt.offset == flags_offset for stmt in result_block.statements)
    monkeypatch.setattr(lift_86_16, "direct_register_result_zero_jcc_8616", lambda *_args, **_kwargs: None)
    fallback_block = pyvex.IRSB(code, 0x1000, arch, opt_level=0)
    assert flags_offset in _guard_reads(fallback_block)
