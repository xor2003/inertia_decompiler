from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16

from inertia_decompiler import cli_stack_byte_offsets as rewrites


@dataclass(frozen=True)
class _AliasState:
    base: object
    offset: int = 0


@dataclass(frozen=True)
class _FakeVirtualVariable:
    varid: int


class _FakeDirtyExpression:
    def __init__(self, dirty):
        self.dirty = dirty
        self.type = SimTypeShort(False)


def _stack_identity(variable):
    if not isinstance(variable, SimStackVariable):
        return None
    return SimpleNamespace(base=getattr(variable, "base", None), offset=getattr(variable, "offset", None))


def _resolve_stack_cvar_at_offset(codegen, offset: int):
    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if isinstance(variable, SimStackVariable) and getattr(variable, "offset", None) == offset:
            return cvar
    return None


@pytest.mark.parametrize("runtime_segment", [False, True])
def test_rewrite_ss_stack_byte_offsets_uses_vvar_alias_for_stack_slot_recovery(
    runtime_segment: bool,
) -> None:
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        project=SimpleNamespace(loader=None),
        variables_in_use={},
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    stack_base_var = SimStackVariable(-10, 1, base="bp", name="s_a", region=0x10010)
    # angr can leave a recovered stack carrier untyped. The lowering pass must
    # still provide CTypeCast with an explicit source type.
    stack_base_cvar = structured_c.CVariable(stack_base_var, variable_type=None, codegen=codegen)
    temp_var = SimRegisterVariable(0, 2, name="vvar_20")
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    cfunc.variables_in_use[stack_base_var] = stack_base_cvar
    cfunc.variables_in_use[temp_var] = temp_cvar

    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            SimTypeShort(False),
            SimTypePointer(SimTypeShort(False)),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Mul",
                    structured_c.CVariable(
                        SimMemoryVariable(
                            0x10006,
                            2,
                            name="inertia_ss",
                            category="inertia_segment_state",
                        )
                        if runtime_segment
                        else SimRegisterVariable(20, 2, name="ss"),
                        codegen=codegen,
                    ),
                    structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                structured_c.CBinaryOp(
                    "Sub",
                    temp_cvar,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                temp_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", stack_base_cvar, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                deref,
                structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    classified = SimpleNamespace(kind="unknown", seg_name="ss", extra_offset=0, addr_expr=deref.operand.expr, cvar=None)

    changed = rewrites._rewrite_ss_stack_byte_offsets(
        project,
        codegen,
        unwrap_c_casts=lambda expr: expr.expr if isinstance(expr, structured_c.CTypeCast) else expr,
        iter_c_nodes_deep=lambda node: iter(getattr(node, "statements", ()) or ()),
        replace_c_children=decompile_replace_c_children,
        c_constant_value=lambda node: node.value if isinstance(node, structured_c.CConstant) else None,
        flatten_c_add_terms=lambda node: (
            [node.lhs, node.rhs] if isinstance(node, structured_c.CBinaryOp) and node.op == "Add" else [node]
        ),
        classify_segmented_dereference=lambda node, _project: classified if node is deref else None,
        strip_segment_scale_from_addr_expr=lambda addr_expr, _project: (
            addr_expr.rhs if isinstance(addr_expr, structured_c.CBinaryOp) else addr_expr
        ),
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=lambda *_args, **_kwargs: False,
        stack_type_for_size=lambda _size: SimTypeShort(False),
        materialize_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
        stack_slot_identity_for_variable=_stack_identity,
        stack_pointer_alias_state=_AliasState,
    )

    assert changed is True
    rewritten = cfunc.statements.statements[1].lhs
    assert isinstance(rewritten, structured_c.CUnaryOp)
    assert rewritten.op == "Dereference"
    assert isinstance(rewritten.operand, structured_c.CTypeCast)
    assert isinstance(rewritten.operand.expr, structured_c.CUnaryOp)
    assert rewritten.operand.expr.op == "Reference"
    assert rewritten.operand.expr.operand is stack_base_cvar


def test_rewrite_ss_stack_byte_offsets_resolves_dirty_virtual_variable_alias():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        project=SimpleNamespace(loader=None),
        variables_in_use={},
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    stack_base_var = SimStackVariable(-10, 1, base="bp", name="s_a", region=0x10010)
    stack_base_cvar = structured_c.CVariable(stack_base_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp_var = SimRegisterVariable(0, 2, name="vvar_20")
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    cfunc.variables_in_use[stack_base_var] = stack_base_cvar
    cfunc.variables_in_use[temp_var] = temp_cvar

    dirty_expr = _FakeDirtyExpression(_FakeVirtualVariable(20))
    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            SimTypeShort(False),
            SimTypePointer(SimTypeShort(False)),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Mul",
                    structured_c.CVariable(SimRegisterVariable(20, 2, name="ss"), codegen=codegen),
                    structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                structured_c.CBinaryOp(
                    "Sub",
                    dirty_expr,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                temp_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", stack_base_cvar, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                deref,
                structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    classified = SimpleNamespace(kind="unknown", seg_name="ss", extra_offset=0, addr_expr=deref.operand.expr, cvar=None)

    changed = rewrites._rewrite_ss_stack_byte_offsets(
        project,
        codegen,
        unwrap_c_casts=lambda expr: expr.expr if isinstance(expr, structured_c.CTypeCast) else expr,
        iter_c_nodes_deep=lambda node: iter(getattr(node, "statements", ()) or ()),
        replace_c_children=decompile_replace_c_children,
        c_constant_value=lambda node: node.value if isinstance(node, structured_c.CConstant) else None,
        flatten_c_add_terms=lambda node: (
            [node.lhs, node.rhs] if isinstance(node, structured_c.CBinaryOp) and node.op == "Add" else [node]
        ),
        classify_segmented_dereference=lambda node, _project: classified if node is deref else None,
        strip_segment_scale_from_addr_expr=lambda addr_expr, _project: (
            addr_expr.rhs if isinstance(addr_expr, structured_c.CBinaryOp) else addr_expr
        ),
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=lambda *_args, **_kwargs: False,
        stack_type_for_size=lambda _size: SimTypeShort(False),
        materialize_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
        stack_slot_identity_for_variable=_stack_identity,
        stack_pointer_alias_state=_AliasState,
    )

    assert changed is True
    rewritten = cfunc.statements.statements[1].lhs
    assert isinstance(rewritten, structured_c.CUnaryOp)
    assert rewritten.operand.expr.operand is stack_base_cvar


def test_rewrite_ss_stack_byte_offsets_resolves_direct_reference_alias_chain():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        project=SimpleNamespace(loader=None),
        variables_in_use={},
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    stack_base_var = SimStackVariable(-8, 1, base="bp", name="s_8", region=0x10010)
    stack_base_cvar = structured_c.CVariable(stack_base_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp_var = SimRegisterVariable(0, 2, name="vvar_20")
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp2_var = SimRegisterVariable(2, 2, name="vvar_24")
    temp2_cvar = structured_c.CVariable(temp2_var, variable_type=SimTypeShort(False), codegen=codegen)
    cfunc.variables_in_use[stack_base_var] = stack_base_cvar
    cfunc.variables_in_use[temp_var] = temp_cvar
    cfunc.variables_in_use[temp2_var] = temp2_cvar

    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            temp2_cvar,
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                temp_cvar,
                structured_c.CUnaryOp("Reference", stack_base_cvar, codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                temp2_cvar,
                structured_c.CBinaryOp(
                    "Sub",
                    temp_cvar,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                deref,
                structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    changed = rewrites._rewrite_ss_stack_byte_offsets(
        project,
        codegen,
        unwrap_c_casts=lambda expr: expr.expr if isinstance(expr, structured_c.CTypeCast) else expr,
        iter_c_nodes_deep=lambda node: iter(getattr(node, "statements", ()) or ()),
        replace_c_children=decompile_replace_c_children,
        c_constant_value=lambda node: node.value if isinstance(node, structured_c.CConstant) else None,
        flatten_c_add_terms=lambda node: (
            [node.lhs, node.rhs] if isinstance(node, structured_c.CBinaryOp) and node.op == "Add" else [node]
        ),
        classify_segmented_dereference=lambda _node, _project: None,
        strip_segment_scale_from_addr_expr=lambda addr_expr, _project: addr_expr,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=lambda *_args, **_kwargs: False,
        stack_type_for_size=lambda _size: SimTypeShort(False),
        materialize_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
        stack_slot_identity_for_variable=_stack_identity,
        stack_pointer_alias_state=_AliasState,
    )

    assert changed is True
    rewritten = cfunc.statements.statements[2].lhs
    assert isinstance(rewritten, structured_c.CUnaryOp)
    assert rewritten.op == "Dereference"
    assert isinstance(rewritten.operand, structured_c.CTypeCast)
    inner = rewritten.operand.expr
    assert isinstance(inner, structured_c.CBinaryOp)
    assert inner.op == "Add"
    assert isinstance(inner.lhs, structured_c.CUnaryOp)
    assert inner.lhs.op == "Reference"
    assert isinstance(inner.lhs.operand, structured_c.CVariable)
    assert getattr(inner.lhs.operand.variable, "offset", None) == -8


def test_rewrite_ss_stack_byte_offsets_resolves_named_vvar_aliases_sharing_one_register():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        project=SimpleNamespace(loader=None),
        variables_in_use={},
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    stack_base_var = SimStackVariable(-8, 1, base="bp", name="s_8", region=0x10010)
    stack_base_cvar = structured_c.CVariable(stack_base_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp_var = SimRegisterVariable(0x30, 2, name="vvar_20")
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp2_var = SimRegisterVariable(0x30, 2, name="vvar_24")
    temp2_cvar = structured_c.CVariable(temp2_var, variable_type=SimTypeShort(False), codegen=codegen)
    cfunc.variables_in_use[stack_base_var] = stack_base_cvar
    cfunc.variables_in_use[temp_var] = temp_cvar
    cfunc.variables_in_use[temp2_var] = temp2_cvar

    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            temp2_cvar,
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                temp_cvar,
                structured_c.CUnaryOp("Reference", stack_base_cvar, codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                temp2_cvar,
                structured_c.CBinaryOp(
                    "Sub",
                    temp_cvar,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                deref,
                structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    changed = rewrites._rewrite_ss_stack_byte_offsets(
        project,
        codegen,
        unwrap_c_casts=lambda expr: expr.expr if isinstance(expr, structured_c.CTypeCast) else expr,
        iter_c_nodes_deep=lambda node: iter(getattr(node, "statements", ()) or ()),
        replace_c_children=decompile_replace_c_children,
        c_constant_value=lambda node: node.value if isinstance(node, structured_c.CConstant) else None,
        flatten_c_add_terms=lambda node: (
            [node.lhs, node.rhs] if isinstance(node, structured_c.CBinaryOp) and node.op == "Add" else [node]
        ),
        classify_segmented_dereference=lambda _node, _project: None,
        strip_segment_scale_from_addr_expr=lambda addr_expr, _project: addr_expr,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=lambda *_args, **_kwargs: False,
        stack_type_for_size=lambda _size: SimTypeShort(False),
        materialize_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
        stack_slot_identity_for_variable=_stack_identity,
        stack_pointer_alias_state=_AliasState,
    )

    assert changed is True
    rewritten = cfunc.statements.statements[2].lhs
    assert isinstance(rewritten, structured_c.CUnaryOp)
    assert rewritten.op == "Dereference"
    assert isinstance(rewritten.operand, structured_c.CTypeCast)
    inner = rewritten.operand.expr
    assert isinstance(inner, structured_c.CBinaryOp)
    assert inner.op == "Add"
    assert isinstance(inner.lhs, structured_c.CUnaryOp)
    assert inner.lhs.op == "Reference"
    assert isinstance(inner.lhs.operand, structured_c.CVariable)
    assert getattr(inner.lhs.operand.variable, "offset", None) == -8


def test_rewrite_ss_stack_byte_offsets_resolves_dirty_assignment_alias_chain():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        project=SimpleNamespace(loader=None),
        variables_in_use={},
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    stack_base_var = SimStackVariable(-8, 1, base="bp", name="s_8", region=0x10010)
    stack_base_cvar = structured_c.CVariable(stack_base_var, variable_type=SimTypeShort(False), codegen=codegen)
    cfunc.variables_in_use[stack_base_var] = stack_base_cvar

    dirty_20 = _FakeDirtyExpression(_FakeVirtualVariable(20))
    dirty_24 = _FakeDirtyExpression(_FakeVirtualVariable(24))
    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            SimTypeShort(False),
            SimTypePointer(SimTypeShort(False)).with_arch(project.arch),
            structured_c.CBinaryOp(
                "Add",
                dirty_24,
                structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                dirty_20,
                structured_c.CUnaryOp("Reference", stack_base_cvar, codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                dirty_24,
                structured_c.CBinaryOp(
                    "Sub",
                    dirty_20,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                deref,
                structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    changed = rewrites._rewrite_ss_stack_byte_offsets(
        project,
        codegen,
        unwrap_c_casts=lambda expr: expr.expr if isinstance(expr, structured_c.CTypeCast) else expr,
        iter_c_nodes_deep=lambda node: iter(getattr(node, "statements", ()) or ()),
        replace_c_children=decompile_replace_c_children,
        c_constant_value=lambda node: node.value if isinstance(node, structured_c.CConstant) else None,
        flatten_c_add_terms=lambda node: (
            [node.lhs, node.rhs] if isinstance(node, structured_c.CBinaryOp) and node.op == "Add" else [node]
        ),
        classify_segmented_dereference=lambda _node, _project: None,
        strip_segment_scale_from_addr_expr=lambda addr_expr, _project: addr_expr,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=lambda *_args, **_kwargs: False,
        stack_type_for_size=lambda _size: SimTypeShort(False),
        materialize_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
        stack_slot_identity_for_variable=_stack_identity,
        stack_pointer_alias_state=_AliasState,
    )

    assert changed is True
    rewritten = cfunc.statements.statements[2].lhs
    assert isinstance(rewritten, structured_c.CUnaryOp)
    assert rewritten.op == "Dereference"
    assert isinstance(rewritten.operand, structured_c.CTypeCast)
    inner = rewritten.operand.expr
    assert isinstance(inner, structured_c.CBinaryOp)
    assert inner.op == "Add"
    assert isinstance(inner.lhs, structured_c.CUnaryOp)
    assert inner.lhs.op == "Reference"
    assert isinstance(inner.lhs.operand, structured_c.CVariable)
    assert getattr(inner.lhs.operand.variable, "offset", None) == -8


def test_rewrite_ss_stack_byte_offsets_uses_sp_virtual_register_as_stack_anchor():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        project=SimpleNamespace(loader=None),
        variables_in_use={},
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    sp_offset, sp_size = project.arch.registers["sp"]
    temp_var = SimRegisterVariable(sp_offset, sp_size, name="vvar_5")
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    cfunc.variables_in_use[temp_var] = temp_cvar

    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            SimTypeShort(False),
            SimTypePointer(SimTypeShort(False)),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Mul",
                    structured_c.CVariable(SimRegisterVariable(20, 2, name="ss"), codegen=codegen),
                    structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                structured_c.CBinaryOp(
                    "Sub",
                    temp_cvar,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                deref, structured_c.CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen
            )
        ],
        addr=0x10010,
        codegen=codegen,
    )

    classified = SimpleNamespace(kind="unknown", seg_name="ss", extra_offset=0, addr_expr=deref.operand.expr, cvar=None)

    changed = rewrites._rewrite_ss_stack_byte_offsets(
        project,
        codegen,
        unwrap_c_casts=lambda expr: expr.expr if isinstance(expr, structured_c.CTypeCast) else expr,
        iter_c_nodes_deep=lambda node: iter(getattr(node, "statements", ()) or ()),
        replace_c_children=decompile_replace_c_children,
        c_constant_value=lambda node: node.value if isinstance(node, structured_c.CConstant) else None,
        flatten_c_add_terms=lambda node: (
            [node.lhs, node.rhs] if isinstance(node, structured_c.CBinaryOp) and node.op == "Add" else [node]
        ),
        classify_segmented_dereference=lambda node, _project: classified if node is deref else None,
        strip_segment_scale_from_addr_expr=lambda addr_expr, _project: (
            addr_expr.rhs if isinstance(addr_expr, structured_c.CBinaryOp) else addr_expr
        ),
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=lambda *_args, **_kwargs: False,
        stack_type_for_size=lambda _size: SimTypeShort(False),
        materialize_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
        stack_slot_identity_for_variable=_stack_identity,
        stack_pointer_alias_state=_AliasState,
    )

    assert changed is True
    rewritten = cfunc.statements.statements[0].lhs
    assert isinstance(rewritten, structured_c.CUnaryOp)
    ref = rewritten.operand.expr
    assert isinstance(ref, structured_c.CBinaryOp)
    assert isinstance(ref.lhs, structured_c.CUnaryOp)
    assert ref.lhs.operand.variable.base == "sp"


def test_rewrite_ss_stack_byte_offsets_handles_shl_segment_scale_alias_chain():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        project=SimpleNamespace(loader=None),
        variables_in_use={},
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    stack_base_var = SimStackVariable(-10, 1, base="bp", name="s_a", region=0x10010)
    stack_base_cvar = structured_c.CVariable(stack_base_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp_var = SimRegisterVariable(0, 2, name="vvar_20")
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    cfunc.variables_in_use[stack_base_var] = stack_base_cvar
    cfunc.variables_in_use[temp_var] = temp_cvar

    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            SimTypeShort(False),
            SimTypePointer(SimTypeShort(False)),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Shl",
                    structured_c.CVariable(SimRegisterVariable(20, 2, name="ss"), codegen=codegen),
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                structured_c.CBinaryOp(
                    "Sub",
                    temp_cvar,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(
                temp_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", stack_base_cvar, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CAssignment(
                deref,
                structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    classified = SimpleNamespace(kind="unknown", seg_name="ss", extra_offset=0, addr_expr=deref.operand.expr, cvar=None)

    changed = rewrites._rewrite_ss_stack_byte_offsets(
        project,
        codegen,
        unwrap_c_casts=lambda expr: expr.expr if isinstance(expr, structured_c.CTypeCast) else expr,
        iter_c_nodes_deep=lambda node: iter(getattr(node, "statements", ()) or ()),
        replace_c_children=decompile_replace_c_children,
        c_constant_value=lambda node: node.value if isinstance(node, structured_c.CConstant) else None,
        flatten_c_add_terms=lambda node: (
            [node.lhs, node.rhs] if isinstance(node, structured_c.CBinaryOp) and node.op == "Add" else [node]
        ),
        classify_segmented_dereference=lambda node, _project: classified if node is deref else None,
        strip_segment_scale_from_addr_expr=lambda addr_expr, _project: (
            addr_expr.rhs if isinstance(addr_expr, structured_c.CBinaryOp) else addr_expr
        ),
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=lambda *_args, **_kwargs: False,
        stack_type_for_size=lambda _size: SimTypeShort(False),
        materialize_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
        stack_slot_identity_for_variable=_stack_identity,
        stack_pointer_alias_state=_AliasState,
    )

    assert changed is True
    rewritten = cfunc.statements.statements[1].lhs
    assert isinstance(rewritten, structured_c.CUnaryOp)
    assert rewritten.operand.expr.operand is stack_base_cvar


def test_rewrite_ss_stack_byte_offsets_resolves_full_linear_carrier_plus_byte_offset():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        project=SimpleNamespace(loader=None),
        variables_in_use={},
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    stack_base_var = SimStackVariable(-6, 1, base="bp", name="iUp", region=0x10010)
    stack_base_cvar = structured_c.CVariable(stack_base_var, variable_type=SimTypeShort(False), codegen=codegen)
    temp_var = SimRegisterVariable(0, 2, name="vvar_1375")
    temp_cvar = structured_c.CVariable(temp_var, variable_type=SimTypeShort(False), codegen=codegen)
    ss_cvar = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    cfunc.variables_in_use[stack_base_var] = stack_base_cvar
    cfunc.variables_in_use[temp_var] = temp_cvar

    full_linear = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Shl",
            ss_cvar,
            structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CUnaryOp("Reference", stack_base_cvar, codegen=codegen),
        codegen=codegen,
    )
    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            temp_cvar,
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    sink_var = SimRegisterVariable(2, 2, name="vvar_1378")
    sink_cvar = structured_c.CVariable(sink_var, variable_type=SimTypeShort(False), codegen=codegen)
    root = structured_c.CStatements(
        [
            structured_c.CAssignment(temp_cvar, full_linear, codegen=codegen),
            structured_c.CAssignment(sink_cvar, deref, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )
    cfunc.statements = root

    changed = rewrites._rewrite_ss_stack_byte_offsets(
        project,
        codegen,
        unwrap_c_casts=lambda expr: expr.expr if isinstance(expr, structured_c.CTypeCast) else expr,
        iter_c_nodes_deep=decompile_iter_c_nodes_deep,
        replace_c_children=decompile_replace_c_children,
        c_constant_value=lambda node: node.value if isinstance(node, structured_c.CConstant) else None,
        flatten_c_add_terms=lambda node: (
            [node.lhs, node.rhs] if isinstance(node, structured_c.CBinaryOp) and node.op == "Add" else [node]
        ),
        classify_segmented_dereference=lambda _node, _project: None,
        strip_segment_scale_from_addr_expr=lambda addr_expr, _project: (
            addr_expr.rhs if isinstance(addr_expr, structured_c.CBinaryOp) else addr_expr
        ),
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=lambda *_args, **_kwargs: False,
        stack_type_for_size=lambda _size: SimTypeShort(False),
        materialize_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
        stack_slot_identity_for_variable=_stack_identity,
        stack_pointer_alias_state=_AliasState,
    )

    assert changed is True
    rewritten = cfunc.statements.statements[1].rhs
    assert isinstance(rewritten, structured_c.CUnaryOp)
    assert isinstance(rewritten.operand, structured_c.CTypeCast)
    assert getattr(rewritten.operand.type.pts_to, "size", None) == 8
    assert rewritten.operand.expr.lhs.operand is stack_base_cvar
    assert rewritten.operand.expr.rhs.value == 1
    assert codegen._inertia_ss_stack_byte_linear_carrier_resolved_8616 >= 1


def test_rewrite_ss_stack_byte_offsets_resolves_virtual_ss_linear_carrier_with_real_strip_refusal():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        project=SimpleNamespace(loader=None),
        variables_in_use={},
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    sp_offset, sp_size = project.arch.registers["sp"]
    ss_offset, ss_size = project.arch.registers["ss"]

    sp_cvar = structured_c.CVariable(
        SimRegisterVariable(sp_offset, sp_size, name="vvar_50"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_cvar = structured_c.CVariable(
        SimRegisterVariable(ss_offset, ss_size, name="vvar_56"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    vvar_58 = structured_c.CVariable(
        SimRegisterVariable(0x40, 2, name="vvar_58"), variable_type=SimTypeShort(False), codegen=codegen
    )
    vvar_1362 = structured_c.CVariable(
        SimRegisterVariable(0x42, 2, name="vvar_1362"), variable_type=SimTypeShort(False), codegen=codegen
    )
    vvar_1363 = structured_c.CVariable(
        SimRegisterVariable(0x44, 2, name="vvar_1363"), variable_type=SimTypeShort(False), codegen=codegen
    )
    vvar_1372 = structured_c.CVariable(
        SimRegisterVariable(0x46, 2, name="vvar_1372"), variable_type=SimTypeShort(False), codegen=codegen
    )
    vvar_1373 = structured_c.CVariable(
        SimRegisterVariable(0x48, 2, name="vvar_1373"), variable_type=SimTypeShort(False), codegen=codegen
    )
    vvar_1375 = structured_c.CVariable(
        SimRegisterVariable(0x4A, 2, name="vvar_1375"), variable_type=SimTypeShort(False), codegen=codegen
    )
    sink_cvar = structured_c.CVariable(
        SimRegisterVariable(0x4C, 2, name="vvar_1378"), variable_type=SimTypeShort(False), codegen=codegen
    )

    full_linear = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp(
            "Shl",
            vvar_1373,
            structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        vvar_1363,
        codegen=codegen,
    )
    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            vvar_1375,
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(
                vvar_58,
                structured_c.CBinaryOp(
                    "Sub",
                    sp_cvar,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CAssignment(vvar_1362, vvar_58, codegen=codegen),
            structured_c.CAssignment(
                vvar_1363,
                structured_c.CBinaryOp(
                    "Sub",
                    vvar_1362,
                    structured_c.CConstant(6, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            structured_c.CAssignment(vvar_1372, ss_cvar, codegen=codegen),
            structured_c.CAssignment(vvar_1373, vvar_1372, codegen=codegen),
            structured_c.CAssignment(vvar_1375, full_linear, codegen=codegen),
            structured_c.CAssignment(sink_cvar, deref, codegen=codegen),
        ],
        addr=0x10010,
        codegen=codegen,
    )

    changed = rewrites._rewrite_ss_stack_byte_offsets(
        project,
        codegen,
        unwrap_c_casts=lambda expr: expr.expr if isinstance(expr, structured_c.CTypeCast) else expr,
        iter_c_nodes_deep=decompile_iter_c_nodes_deep,
        replace_c_children=decompile_replace_c_children,
        c_constant_value=lambda node: node.value if isinstance(node, structured_c.CConstant) else None,
        flatten_c_add_terms=lambda node: (
            [node.lhs, node.rhs] if isinstance(node, structured_c.CBinaryOp) and node.op == "Add" else [node]
        ),
        classify_segmented_dereference=lambda _node, _project: None,
        strip_segment_scale_from_addr_expr=lambda _addr_expr, _project: None,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=lambda *_args, **_kwargs: False,
        stack_type_for_size=lambda _size: SimTypeShort(False),
        materialize_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
        stack_slot_identity_for_variable=_stack_identity,
        stack_pointer_alias_state=_AliasState,
    )

    assert changed is True
    rewritten = cfunc.statements.statements[-1].rhs
    assert isinstance(rewritten, structured_c.CUnaryOp)
    assert isinstance(rewritten.operand, structured_c.CTypeCast)
    assert getattr(rewritten.operand.type.pts_to, "size", None) == 8
    ref = rewritten.operand.expr
    assert isinstance(ref, structured_c.CBinaryOp)
    assert ref.lhs.operand.variable.base == "sp"
    assert ref.rhs.value == -7
    assert codegen._inertia_ss_stack_byte_segment_strip_materialized_8616 >= 1


def test_rewrite_ss_stack_byte_offsets_rewrites_for_loop_iterator_store():
    project = SimpleNamespace(arch=Arch86_16())
    cfunc = SimpleNamespace(
        addr=0x10010,
        project=SimpleNamespace(loader=None),
        variables_in_use={},
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)

    stack_base_var = SimStackVariable(-4, 1, base="bp", name="s_4", region=0x10010)
    stack_base_cvar = structured_c.CVariable(stack_base_var, variable_type=SimTypeShort(False), codegen=codegen)
    cfunc.variables_in_use[stack_base_var] = stack_base_cvar

    iterator_deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(
            SimTypeShort(False),
            SimTypePointer(SimTypeShort(False)),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Shl",
                    structured_c.CVariable(SimRegisterVariable(20, 2, name="ss"), codegen=codegen),
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", stack_base_cvar, codegen=codegen),
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    loop = structured_c.CForLoop(
        None,
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        structured_c.CAssignment(
            iterator_deref,
            structured_c.CConstant(7, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CStatements([], addr=0x10010, codegen=codegen),
        codegen=codegen,
    )

    root = structured_c.CStatements([loop], addr=0x10010, codegen=codegen)
    cfunc.statements = root

    classified = SimpleNamespace(
        kind="stack", seg_name="ss", extra_offset=1, addr_expr=iterator_deref.operand.expr, cvar=stack_base_cvar
    )

    changed = rewrites._rewrite_ss_stack_byte_offsets(
        project,
        codegen,
        unwrap_c_casts=lambda expr: expr.expr if isinstance(expr, structured_c.CTypeCast) else expr,
        iter_c_nodes_deep=decompile_iter_c_nodes_deep,
        replace_c_children=decompile_replace_c_children,
        c_constant_value=lambda node: node.value if isinstance(node, structured_c.CConstant) else None,
        flatten_c_add_terms=lambda node: (
            [node.lhs, node.rhs] if isinstance(node, structured_c.CBinaryOp) and node.op == "Add" else [node]
        ),
        classify_segmented_dereference=lambda node, _project: classified if node is iterator_deref else None,
        strip_segment_scale_from_addr_expr=lambda addr_expr, _project: (
            addr_expr.rhs if isinstance(addr_expr, structured_c.CBinaryOp) else addr_expr
        ),
        resolve_stack_cvar_at_offset=lambda _codegen, offset: stack_base_cvar if offset == -3 else None,
        promote_direct_stack_cvariable=lambda *_args, **_kwargs: False,
        stack_type_for_size=lambda _size: SimTypeShort(False),
        materialize_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
        stack_slot_identity_for_variable=_stack_identity,
        stack_pointer_alias_state=_AliasState,
    )

    assert changed is True
    rewritten = loop.iterator.lhs
    assert isinstance(rewritten, structured_c.CUnaryOp)
    assert rewritten.op == "Dereference"
    assert isinstance(rewritten.operand, structured_c.CTypeCast)
    assert isinstance(rewritten.operand.expr, structured_c.CBinaryOp)


def decompile_replace_c_children(node, transform):
    changed = False
    if isinstance(node, structured_c.CStatements):
        new_statements = []
        for stmt in node.statements:
            new_stmt = transform(stmt)
            new_statements.append(new_stmt)
            changed |= new_stmt is not stmt
        if changed:
            node.statements = new_statements
        for stmt in node.statements:
            changed |= decompile_replace_c_children(stmt, transform)
        return changed
    for attr in ("lhs", "rhs", "expr", "operand", "initializer", "iterator", "condition", "body"):
        child = getattr(node, attr, None)
        if child is None:
            continue
        new_child = transform(child)
        if new_child is not child:
            setattr(node, attr, new_child)
            changed = True
            child = new_child
        if isinstance(
            child, (structured_c.CBinaryOp, structured_c.CUnaryOp, structured_c.CTypeCast, structured_c.CAssignment)
        ):
            changed |= decompile_replace_c_children(child, transform)
    return changed


_DEEP_C_NODE_TYPES = (
    structured_c.CBinaryOp,
    structured_c.CUnaryOp,
    structured_c.CTypeCast,
    structured_c.CAssignment,
    structured_c.CStatements,
    structured_c.CForLoop,
    structured_c.CVariable,
    structured_c.CConstant,
)


def decompile_iter_c_nodes_deep(node, seen=None):
    if seen is None:
        seen = set()
    if node is None:
        return
    node_id = id(node)
    if node_id in seen:
        return
    seen.add(node_id)
    yield node
    yield from _iter_deep_c_children(node, seen)


def _iter_deep_c_children(node, seen):
    for attr in dir(node):
        if attr.startswith("_") or attr == "codegen":
            continue
        try:
            value = getattr(node, attr)
        except Exception:
            continue
        if isinstance(value, _DEEP_C_NODE_TYPES):
            yield from decompile_iter_c_nodes_deep(value, seen)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, _DEEP_C_NODE_TYPES):
                    yield from decompile_iter_c_nodes_deep(item, seen)
