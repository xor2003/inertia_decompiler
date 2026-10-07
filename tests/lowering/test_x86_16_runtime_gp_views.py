from __future__ import annotations

from types import SimpleNamespace

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.gp_register_state import (
    runtime_gp_expression_view_8616,
    runtime_gp_state_expr_8616,
)
from inertia.lowering.real_mode_linear import (
    _stack_offset_from_expr_8616,
)


def _codegen() -> SimpleNamespace:
    """Return the minimum modern-angr structured-C boundary for these tests."""
    arch = Arch86_16()
    return SimpleNamespace(
        cstyle_null_cmp=False,
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=arch),
    )


def test_runtime_gp_owner_classifies_canonical_bp_projection() -> None:
    """Recognize the typed BP view without symbol or C-text matching."""
    codegen = _codegen()
    expression = runtime_gp_state_expr_8616(
        "bp",
        codegen=codegen,
        function_addr=0x1000,
    )

    view = runtime_gp_expression_view_8616(expression)

    assert view is not None
    assert view.register_name == "bp"
    assert view.parent_name == "ebp"
    assert view.bit_shift == 0
    assert view.width == 2


def test_stack_offset_consumes_typed_runtime_bp_projection() -> None:
    """Treat canonical runtime BP as the zero base of machine-BP storage."""
    codegen = _codegen()
    expression = runtime_gp_state_expr_8616(
        "bp",
        codegen=codegen,
        function_addr=0x1000,
    )

    assert expression is not None
    assert _stack_offset_from_expr_8616(
        expression,
        codegen.project,
        codegen,
    ) == 0
