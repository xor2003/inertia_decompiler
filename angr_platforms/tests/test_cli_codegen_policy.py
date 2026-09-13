"""Generated source must retain expressions regardless of display complexity."""

import sys
from itertools import count
from types import SimpleNamespace

import pytest
from angr.ailment.expression import BinaryOp, Const
from angr.analyses.decompiler.structured_codegen.c import CConstant, CStructuredCodeGenerator
from angr.sim_type import SimTypeInt
from archinfo import ArchX86

from inertia_decompiler.cli_decompilation import _preferred_expr_collapse_depth


@pytest.mark.parametrize("blocks,size,wrapper,tiny", [
    (1, 32, False, False),
    (8, 128, True, False),
    (8, 128, False, True),
    (24, 256, False, False),
    (64, 1024, False, False),
    (100, 4096, False, False),
])
def test_generated_source_disables_expression_display_truncation(
    blocks: int, size: int, wrapper: bool, tiny: bool,
) -> None:
    """Every function class must disable angr's UI-only expression cutoff."""
    depth = _preferred_expr_collapse_depth(
        blocks, size, wrapper_like=wrapper, tiny_single_call_helper=tiny,
    )
    assert depth == sys.maxsize


@pytest.mark.parametrize("display_only", [False, True])
def test_native_codegen_cutoff_preserves_exported_binary_expression(display_only: bool) -> None:
    """Exercise the native renderer and retain a truncating control case."""
    leaf = Const(0, 1, 32)
    expression = leaf
    for index in range(5):
        expression = BinaryOp(index, "Add", [expression, leaf], False, bits=32)
    cutoff = 2 if display_only else _preferred_expr_collapse_depth(1, 32)
    node_ids = count()
    architecture = ArchX86()
    context = SimpleNamespace(
        _variable_map=SimpleNamespace(variable=lambda _: None),
        binop_depth_cutoff=cutoff,
        next_ident=lambda name: name,
        next_node_idx=lambda: next(node_ids),
        cstyle_null_cmp=False,
        project=SimpleNamespace(arch=architecture),
    )

    def render(node):
        if isinstance(node, Const):
            return CConstant(node.value, SimTypeInt(signed=False).with_arch(architecture), codegen=context)
        return CStructuredCodeGenerator._handle_Expr_BinaryOp(context, node)

    context._handle = lambda node, **_kwargs: render(node)
    rendered = render(expression)
    assert rendered.collapsed is display_only
