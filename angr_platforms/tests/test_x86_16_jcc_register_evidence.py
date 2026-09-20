"""Comparison cleanup must not invent an uninitialized register expression."""

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16 import decompiler_postprocess_jcc as jcc
from angr_platforms.X86_16.arch_86_16 import Arch86_16


@pytest.mark.parametrize("source", ["missing", "state", "instruction", "stack"])
def test_comparison_register_requires_existing_value(monkeypatch, source):
    """Keep the proven value identity or refuse, never fabricate a bare AX."""
    value = object()
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(project=project, next_ident=lambda name: name, next_node_idx=lambda: 0)
    instruction = 0x1000
    monkeypatch.setattr(
        jcc,
        "_lookup_prior_register_stack_load_8616",
        lambda *_args: value if source == "stack" else None,
    )
    result = jcc._resolve_cmp_operand_expr_8616(
        project,
        codegen,
        SimpleNamespace(type=1, reg=0, size=2),
        {"ax": value} if source == "state" else {},
        None,
        lambda _reg: "ax",
        {(instruction, "ax", 2): value} if source == "instruction" else {},
        instruction,
    )
    assert result is (None if source == "missing" else value)
