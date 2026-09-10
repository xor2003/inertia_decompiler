"""C rendering must preserve expression trees and pass strict compiler warnings."""

import subprocess
from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeInt
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.codegen_parentheses import apply_codegen_parentheses_8616


@pytest.mark.parametrize("parent,child", [
    ("And", "Add"), ("Or", "And"), ("Xor", "And"), ("Or", "Xor"),
    ("Shl", "Add"), ("Shr", "Add"), ("LogicalOr", "LogicalAnd"),
])
@pytest.mark.parametrize("side", ["left", "right"])
def test_mixed_operator_rendering_is_warning_clean(parent: str, child: str, side: str) -> None:
    indices = count()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()), const_formats={}, cstyle_null_cmp=False,
        next_node_idx=lambda: next(indices), next_ident=lambda name: name,
    )
    lhs = c.CConstant(7, SimTypeInt(False), codegen=codegen)
    rhs = c.CConstant(1, SimTypeInt(False), codegen=codegen)
    nested = c.CBinaryOp(child, lhs, rhs, codegen=codegen)
    expression = c.CBinaryOp(
        parent, nested if side == "left" else lhs, nested if side == "right" else rhs, codegen=codegen,
    )
    original = (expression.lhs, expression.rhs, nested.lhs, nested.rhs)
    rendered = "".join(text for text, _node in expression.c_repr_chunks())
    expected = {
        ("And", "Add"): (0, 0), ("Or", "And"): (1, 7), ("Xor", "And"): (0, 6),
        ("Or", "Xor"): (7, 7), ("Shl", "Add"): (16, 1792),
        ("Shr", "Add"): (4, 0), ("LogicalOr", "LogicalAnd"): (1, 1),
    }[(parent, child)][side == "right"]
    compiled = subprocess.run(
        ["gcc", "-x", "c", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsyntax-only", "-"],
        input=(f"unsigned f(void) {{ return {rendered}; }}\n"
               f'_Static_assert(({rendered}) == {expected}, "operand grouping changed the value");\n'),
        text=True, capture_output=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr
    assert original == (expression.lhs, expression.rhs, nested.lhs, nested.rhs)
    assert expression.op == parent and nested.op == child


def test_grouping_installation_is_idempotent() -> None:
    installed = c.CBinaryOp._c_repr_chunks
    apply_codegen_parentheses_8616()
    assert c.CBinaryOp._c_repr_chunks is installed


def test_other_architectures_keep_native_rendering() -> None:
    indices = count()
    arch = Arch86_16()
    arch.name = "X86"
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch), const_formats={}, cstyle_null_cmp=False,
        next_node_idx=lambda: next(indices), next_ident=lambda name: name,
    )
    lhs = c.CConstant(7, SimTypeInt(False), codegen=codegen)
    rhs = c.CConstant(1, SimTypeInt(False), codegen=codegen)
    nested = c.CBinaryOp("Add", lhs, rhs, codegen=codegen)
    expression = c.CBinaryOp("And", nested, rhs, codegen=codegen)
    assert "".join(text for text, _node in expression.c_repr_chunks()) == "7 + 1 & 1"
