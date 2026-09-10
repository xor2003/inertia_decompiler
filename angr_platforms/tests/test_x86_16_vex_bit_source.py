"""Selected-bit projection preserves snapshots and refuses unknown proofs."""

import claripy
import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.vex_bit_source import project_bit_source_8616
from pyvex.block import IRTypeEnv
from pyvex.const import U8, U16, U32
from pyvex.expr import Binop, Const, Get, RdTmp
from pyvex.stmt import Put, WrTmp


@pytest.mark.parametrize("width", [8, 16, 32])
@pytest.mark.parametrize("position", ["low", "middle", "high"])
@pytest.mark.parametrize("reverse", [False, True])
def test_selected_bit_is_equal_for_all_inputs_and_keeps_captured_read(width, position, reverse):
    bit = {"low": 0, "middle": width // 2, "high": width - 1}[position]
    env = IRTypeEnv(Arch86_16(), [f"Ity_I{width}"] * 5)
    constant = {8: U8, 16: U16, 32: U32}[width]
    mask = 1 << bit
    inverse = ((1 << width) - 1) ^ mask
    left = Binop(f"Iop_And{width}", [RdTmp(0), Const(constant(mask))])
    right = Binop(f"Iop_And{width}", [RdTmp(1), Const(constant(inverse))])
    args = [RdTmp(3), RdTmp(2)] if reverse else [RdTmp(2), RdTmp(3)]
    statements = [WrTmp(0, Get(36, f"Ity_I{width}")), WrTmp(1, Get(0, f"Ity_I{width}")),
                  WrTmp(2, left), WrTmp(3, right), WrTmp(4, Binop(f"Iop_Or{width}", args)),
                  Put(Const(constant(0)), 36)]
    root = RdTmp(4)
    proof = project_bit_source_8616(root, statements, env, bit=bit)
    assert isinstance(proof.source, RdTmp) and proof.source.tmp == 0
    assert proof.raw_fact_count == proof.normalized_fact_count == proof.classified_fact_count == proof.materialized_count == 1
    assert proof.failure_count == 0
    old, new = claripy.BVS("old", width), claripy.BVS("new", width)
    original = (old & mask) | (new & inverse)
    assert not claripy.Solver().satisfiable(extra_constraints=[original[bit:bit] != old[bit:bit]])
    assert statements[-1].offset == 36


@pytest.mark.parametrize("case", ["unknown", "live_bit", "mixed_width", "cycle", "duplicate", "invalid_bit"])
def test_unproven_projection_keeps_original_atom(case):
    env = IRTypeEnv(Arch86_16(), ["Ity_I16"] * 3)
    statements = [WrTmp(0, Get(36, "Ity_I16"))]
    operation = "Iop_Add16" if case == "unknown" else "Iop_Or16"
    constant = Const(U16(0x400 if case == "live_bit" else 0))
    if case == "mixed_width":
        constant = Const(U32(0))
    statements.append(WrTmp(1, Binop(operation, [RdTmp(0), constant])))
    if case == "cycle":
        statements[0] = WrTmp(0, RdTmp(1))
    elif case == "duplicate":
        statements.append(WrTmp(0, Const(U16(0))))
    root = RdTmp(1)
    proof = project_bit_source_8616(root, statements, env, bit=16 if case == "invalid_bit" else 10)
    assert proof.source is root
    assert proof.materialized_count == 0 and proof.failure_count == 1
