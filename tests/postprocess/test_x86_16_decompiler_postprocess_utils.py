from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CSwitchCase,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
import inertia.postprocess.decompiler_postprocess_utils as decompiler_postprocess_utils
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.postprocess.decompiler_postprocess_loads import (
    _global_load_addr_8616,
    _match_global_scaled_high_byte_8616,
    _segmented_load_addr_8616,
)
from inertia.postprocess.decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _match_real_mode_linear_expr_8616,
    _replace_c_children_8616,
)


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _segmented_linear(project, seg_name: str, offset: int, codegen):
    seg = _reg(project, seg_name, codegen)
    return CBinaryOp(
        "Add",
        CBinaryOp("Mul", seg, _const(16, codegen), codegen=codegen),
        _const(offset, codegen),
        codegen=codegen,
    )


def _global_deref(addr: int, codegen):
    return CVariable(
        SimMemoryVariable(addr, 1),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_postprocess_utils_do_not_infer_ds_from_bare_constant():
    project = _project()
    codegen = _DummyCodegen()
    deref = CUnaryOp("Dereference", _const(0x234, codegen), codegen=codegen)

    assert _match_real_mode_linear_expr_8616(_const(0x234, codegen), project) == (None, None)
    assert _global_load_addr_8616(deref) is None
    assert _segmented_load_addr_8616(deref, project) == (None, None)


def test_postprocess_utils_match_explicit_segment_times_16_plus_offset():
    project = _project()
    codegen = _DummyCodegen()

    assert _match_real_mode_linear_expr_8616(_segmented_linear(project, "ds", 0x234, codegen), project) == ("ds", 0x234)
    assert _match_real_mode_linear_expr_8616(_segmented_linear(project, "ss", 0x18, codegen), project) == ("ss", 0x18)


def test_postprocess_utils_match_ss_shift_by_four_as_linear_segment_form():
    project = _project()
    codegen = _DummyCodegen()
    ss = _reg(project, "ss", codegen)
    expr = CBinaryOp("Shl", ss, _const(4, codegen), codegen=codegen)

    assert _match_real_mode_linear_expr_8616(expr, project) == ("ss", 0)


def test_postprocess_utils_keep_ds_dereference_loads_explicit():
    project = _project()
    codegen = _DummyCodegen()
    deref = CUnaryOp("Dereference", _segmented_linear(project, "ds", 0x234, codegen), codegen=codegen)

    assert _global_load_addr_8616(deref) is None
    assert _segmented_load_addr_8616(deref, project) == ("ds", 0x234)


def test_postprocess_walk_bypasses_container_helper_for_direct_and_scalar_slots(
    monkeypatch,
):
    codegen = _DummyCodegen()
    lhs = _const(1, codegen)
    rhs = _const(2, codegen)
    expression = CBinaryOp("Or", lhs, rhs, codegen=codegen)

    def refuse_container_walk(*_args, **_kwargs):
        raise AssertionError("direct and scalar slots must bypass container walk")

    monkeypatch.setattr(
        decompiler_postprocess_utils,
        "_iter_c_node_children_8616",
        refuse_container_walk,
    )

    assert tuple(_iter_c_nodes_deep_8616(expression)) == (expression, rhs, lhs)


def test_postprocess_utils_match_scaled_high_byte_only_for_true_globals():
    codegen = _DummyCodegen()
    global_high = CBinaryOp("Mul", _global_deref(0x235, codegen), _const(0x100, codegen), codegen=codegen)
    ds_deref = CUnaryOp("Dereference", _segmented_linear(_project(), "ds", 0x235, codegen), codegen=codegen)
    ds_high = CBinaryOp("Mul", ds_deref, _const(0x100, codegen), codegen=codegen)

    assert _match_global_scaled_high_byte_8616(global_high) == 0x235
    assert _match_global_scaled_high_byte_8616(ds_high) is None


def test_replace_c_children_rewrites_switch_case_tuple_bodies_and_default():
    codegen = _DummyCodegen()
    case_helper = CFunctionCall("SEG_U16", None, [_reg(codegen.project, "ds", codegen), _const(0x0BA2, codegen)], codegen=codegen)
    default_helper = CFunctionCall(
        "SEG_U16",
        None,
        [_reg(codegen.project, "ds", codegen), _const(0x0B46, codegen)],
        codegen=codegen,
    )
    case_body = CStatements([CExpressionStatement(case_helper, codegen=codegen)], codegen=codegen)
    default_body = CStatements([CExpressionStatement(default_helper, codegen=codegen)], codegen=codegen)
    replacement = CVariable(
        SimMemoryVariable(0x0BA2, 2, name="cRow"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    switch = CSwitchCase(_reg(codegen.project, "ax", codegen), [(69, case_body)], default_body, codegen=codegen)

    def transform(node):
        if isinstance(node, CFunctionCall) and node.callee_target == "SEG_U16":
            return replacement
        return node

    changed = _replace_c_children_8616(switch, transform)

    assert changed is True
    assert switch.cases[0][1].statements[0].expr is replacement
    assert switch.default.statements[0].expr is replacement


def test_postprocess_replace_only_reads_declared_child_slots():
    """Postprocess replacement must not probe unrelated AST descriptors."""

    class _SyntheticStructuredNode:
        __module__ = "angr.analyses.decompiler.structured_codegen.synthetic"
        __slots__ = ("lhs", "rhs_read_count")

        def __init__(self, lhs: object) -> None:
            self.lhs = lhs
            self.rhs_read_count = 0

        @property
        def rhs(self) -> None:
            self.rhs_read_count += 1
            return None

    codegen = _DummyCodegen()
    original = _const(1, codegen)
    replacement = _const(2, codegen)
    root = _SyntheticStructuredNode(original)

    changed = _replace_c_children_8616(
        root,
        lambda node: replacement if node is original else node,
    )

    assert changed is True
    assert root.lhs is replacement
    assert root.rhs_read_count == 0
