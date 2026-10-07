from __future__ import annotations

import inertia.alias.stack_lowering as alias_stack_lowering
import inertia.lowering.stack_lowering as stack_lowering


def test_x86_16_alias_stack_lowering_bridge_exports_canonical_helpers() -> None:
    assert alias_stack_lowering.__all__ == (
        "_canonicalize_stack_cvar_expr",
        "_canonicalize_stack_cvars",
        "_materialize_stack_cvar_at_offset",
        "_resolve_stack_cvar_at_offset",
        "_resolve_stack_cvar_from_addr_expr",
        "run_stack_lowering_pass_8616",
    )
    assert alias_stack_lowering._canonicalize_stack_cvar_expr is stack_lowering._canonicalize_stack_cvar_expr
    assert alias_stack_lowering._canonicalize_stack_cvars is stack_lowering._canonicalize_stack_cvars
    assert alias_stack_lowering._materialize_stack_cvar_at_offset is stack_lowering._materialize_stack_cvar_at_offset
    assert alias_stack_lowering._resolve_stack_cvar_at_offset is stack_lowering._resolve_stack_cvar_at_offset
    assert alias_stack_lowering._resolve_stack_cvar_from_addr_expr is stack_lowering._resolve_stack_cvar_from_addr_expr
    assert alias_stack_lowering.run_stack_lowering_pass_8616 is stack_lowering.run_stack_lowering_pass_8616
