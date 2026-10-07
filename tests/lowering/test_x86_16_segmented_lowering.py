from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.segmented_lowering import (
    _classify_segmented_addr_expr,
    _match_real_mode_linear_expr,
    _match_segmented_dereference,
)


def _const(value: int, codegen: object) -> structured_c.CConstant:
    return structured_c.CConstant(value, SimTypeShort(False).with_arch(codegen.project.arch), codegen=codegen)


def _reg(project: object, name: str, codegen: object) -> structured_c.CVariable:
    reg_offset, reg_size = project.arch.registers[name]
    return structured_c.CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _flatten_add_terms(node: object) -> list[object]:
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Add":
        return [*_flatten_add_terms(node.lhs), *_flatten_add_terms(node.rhs)]
    return [node]


def _unwrap_c_casts(node: object) -> object:
    return node.expr if isinstance(node, structured_c.CTypeCast) else node


def _c_constant_value(node: object) -> int | None:
    return node.value if isinstance(node, structured_c.CConstant) and isinstance(node.value, int) else None


def _normalize_16bit_signed_offset(value: object) -> int:
    raw = value if isinstance(value, int) else 0
    return ((raw + 0x8000) & 0xFFFF) - 0x8000


def _classify(node: object, project: object):
    cache_store: dict[str, dict[int, object]] = {}
    return _classify_segmented_addr_expr(
        node,
        project,
        project_rewrite_cache=lambda _project: cache_store,
        flatten_c_add_terms=_flatten_add_terms,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
        match_stack_cvar_and_offset=lambda _node: None,
        normalize_16bit_signed_offset=_normalize_16bit_signed_offset,
        stack_slot_identity_for_variable=lambda _variable: None,
    )


def _segmented_linear(project: object, seg_name: str, offset: int, codegen: object) -> structured_c.CBinaryOp:
    return structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp("Shl", _reg(project, seg_name, codegen), _const(4, codegen), codegen=codegen),
        _const(offset, codegen),
        codegen=codegen,
    )


def test_classify_segmented_addr_expr_treats_sp_register_as_stack_anchor() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(addr=0x1000),
        next_idx=lambda _name: 0,
        cstyle_null_cmp=False,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    expr = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp("Shl", _reg(project, "ss", codegen), _const(4, codegen), codegen=codegen),
        structured_c.CBinaryOp("Sub", _reg(project, "sp", codegen), _const(2, codegen), codegen=codegen),
        codegen=codegen,
    )

    classified = _classify(expr, project)

    assert classified is not None
    assert classified.kind == "stack"
    assert classified.seg_name == "ss"
    assert classified.stack_var is not None
    assert classified.stack_var.base == "sp"
    assert classified.extra_offset == -2


def test_match_segmented_dereference_returns_explicit_segment_and_offset() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    deref = structured_c.CUnaryOp("Dereference", _segmented_linear(project, "ds", 0x234, codegen), codegen=codegen)
    cache_store: dict[str, dict[int, object]] = {}

    result = _match_segmented_dereference(
        deref,
        project,
        project_rewrite_cache=lambda _project: cache_store,
        classify_segmented_dereference=lambda node, classify_project: _classify_segmented_addr_expr(
            node.operand if isinstance(node, structured_c.CUnaryOp) else node,
            classify_project,
            project_rewrite_cache=lambda _project: cache_store,
            flatten_c_add_terms=_flatten_add_terms,
            unwrap_c_casts=_unwrap_c_casts,
            c_constant_value=_c_constant_value,
            match_stack_cvar_and_offset=lambda _node: None,
            normalize_16bit_signed_offset=_normalize_16bit_signed_offset,
            stack_slot_identity_for_variable=lambda _variable: None,
        ),
    )

    assert result == ("ds", 0x234)


def test_match_real_mode_linear_expr_refuses_bare_constant() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(project=project, next_idx=lambda _name: 0, cstyle_null_cmp=False, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)
    cache_store: dict[str, dict[int, object]] = {}

    result = _match_real_mode_linear_expr(
        _const(0x234, codegen),
        project,
        project_rewrite_cache=lambda _project: cache_store,
        classify_segmented_addr_expr=lambda node, classify_project: _classify_segmented_addr_expr(
            node,
            classify_project,
            project_rewrite_cache=lambda _project: cache_store,
            flatten_c_add_terms=_flatten_add_terms,
            unwrap_c_casts=_unwrap_c_casts,
            c_constant_value=_c_constant_value,
            match_stack_cvar_and_offset=lambda _node: None,
            normalize_16bit_signed_offset=_normalize_16bit_signed_offset,
            stack_slot_identity_for_variable=lambda _variable: None,
        ),
    )

    assert result == (None, None)
