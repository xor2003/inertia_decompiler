from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CExpressionStatement,
    CIfElse,
    CMultiStatementExpression,
    CStatements,
    CSwitchCase,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16 import c_ast_utils, decompiler_postprocess_utils
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.c_ast_utils import (
    _c_ast_cycle_path_8616,
    _clone_c_ast_tree_8616,
    _iter_c_nodes_deep_8616,
    _iter_c_statement_nodes_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
)


class _DummyCodegen:
    def __init__(self) -> None:
        self._index = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._index += 1
        return self._index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


@pytest.mark.parametrize("switch", (False, True))
def test_replace_c_children_preserves_conditional_pair_and_case_structure(switch: bool) -> None:
    """Typed boundary views must preserve replacement and idempotence behavior."""
    codegen = _DummyCodegen()
    original = CConstant(1, SimTypeShort(False), codegen=codegen)
    replacement = CConstant(2, SimTypeShort(False), codegen=codegen)
    body = CStatements([], codegen=codegen)
    new_body = CStatements([], codegen=codegen)
    root = (
        CSwitchCase(original, [(7, body)], None, codegen=codegen)
        if switch else CIfElse([(original, body)], codegen=codegen)
    )

    def replace(node: object) -> object:
        if node is original:
            return replacement
        return new_body if node is body else node

    assert _replace_c_children_8616(root, replace)
    if switch:
        assert root.switch is replacement
        assert root.cases == [(7, new_body)]
        assert root.default is None
    else:
        assert root.condition_and_nodes == [(replacement, new_body)]
        assert root.else_node is None
    assert not _replace_c_children_8616(root, replace)


def test_c_ast_cycle_path_reports_active_path_cycle() -> None:
    codegen = _DummyCodegen()
    constant = CConstant(1, SimTypeShort(False), codegen=codegen)
    outer = CBinaryOp("Or", constant, constant, codegen=codegen)
    inner = CBinaryOp("Or", outer, constant, codegen=codegen)
    outer.lhs = inner
    root = CStatements([outer], codegen=codegen)

    cycle = _c_ast_cycle_path_8616(root)

    assert cycle
    assert cycle[-1].endswith("(cycle-to=1)")


def test_clone_c_ast_tree_preserves_boundary_objects_without_sharing_nodes() -> None:
    codegen = _DummyCodegen()
    variable = SimRegisterVariable(0, 2, name="ax")
    source = CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
    expression = CBinaryOp(
        "Or",
        source,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    cloned = _clone_c_ast_tree_8616(expression)

    assert isinstance(cloned, CBinaryOp)
    assert cloned is not expression
    assert cloned.lhs is not expression.lhs
    assert cloned.lhs.variable is variable
    assert cloned.codegen is codegen
    assert _c_ast_cycle_path_8616(cloned) == ()


def test_statement_walk_does_not_descend_into_expression_trees() -> None:
    codegen = _DummyCodegen()
    constant = CConstant(1, SimTypeShort(False), codegen=codegen)
    expression = CBinaryOp("Or", constant, constant, codegen=codegen)
    statement = CExpressionStatement(expression, codegen=codegen)
    root = CStatements([statement], codegen=codegen)

    nodes = tuple(_iter_c_statement_nodes_8616(root))

    assert nodes == (root, statement)
    assert expression not in nodes


def test_deep_walk_visits_shared_nodes_once_and_refuses_cycles() -> None:
    codegen = _DummyCodegen()
    constant = CConstant(1, SimTypeShort(False), codegen=codegen)
    expression = CBinaryOp("Or", constant, constant, codegen=codegen)
    expression.lhs = expression
    root = CStatements([expression, expression], codegen=codegen)

    nodes = tuple(_iter_c_nodes_deep_8616(root))

    assert nodes == (root, expression, constant)


def test_deep_walk_bypasses_container_helper_for_direct_and_scalar_slots(
    monkeypatch,
) -> None:
    """Direct node and scalar slots must not enter recursive container logic."""
    codegen = _DummyCodegen()
    lhs = CConstant(1, SimTypeShort(False), codegen=codegen)
    rhs = CConstant(2, SimTypeShort(False), codegen=codegen)
    expression = CBinaryOp("Or", lhs, rhs, codegen=codegen)

    def refuse_container_walk(*_args, **_kwargs):
        raise AssertionError("direct and scalar slots must bypass container walk")

    monkeypatch.setattr(
        c_ast_utils,
        "_iter_c_node_children_8616",
        refuse_container_walk,
    )

    assert tuple(_iter_c_nodes_deep_8616(expression)) == (expression, rhs, lhs)


def test_replace_c_children_only_reads_declared_child_slots() -> None:
    """Replacement must not probe unrelated third-party node descriptors."""

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
    original = CConstant(1, SimTypeShort(False), codegen=codegen)
    replacement = CConstant(2, SimTypeShort(False), codegen=codegen)
    root = _SyntheticStructuredNode(original)

    changed = _replace_c_children_8616(
        root,
        lambda node: replacement if node is original else node,
    )

    assert changed is True
    assert root.lhs is replacement
    assert root.rhs_read_count == 0


def test_replace_c_children_descends_into_multi_statement_expression() -> None:
    """Replacement must reach statements embedded in comma expressions."""
    codegen = _DummyCodegen()
    original = CConstant(1, SimTypeShort(False), codegen=codegen)
    replacement = CConstant(2, SimTypeShort(False), codegen=codegen)
    embedded = CExpressionStatement(original, codegen=codegen)
    root = CMultiStatementExpression(
        CStatements([embedded], codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    changed = _replace_c_children_8616(
        root,
        lambda node: replacement if node is original else node,
    )

    assert changed is True
    assert embedded.expr is replacement


@pytest.mark.parametrize("compare", [_same_c_expression_8616, decompiler_postprocess_utils._same_c_expression_8616])
@pytest.mark.parametrize("changed", [{}, {"offset": 3}, {"size": 1}, {"base": "sp"}, {"region": 0x2000}])
def test_expression_comparison_preserves_stack_storage_coordinates(changed, compare):
    codegen = _DummyCodegen()
    coordinates = {"offset": 2, "size": 2, "base": "bp", "region": 0x1000}
    lhs = CVariable(SimStackVariable(**coordinates), codegen=codegen)
    rhs = CVariable(SimStackVariable(**(coordinates | changed)), codegen=codegen)
    assert compare(lhs, rhs) is (not changed)


@pytest.mark.parametrize("attribute", ["reg_offset", "reg", "variable_offset"])
def test_dirty_expression_comparison_preserves_register_width_and_precedence(attribute):
    codegen = _DummyCodegen()
    original = {attribute: 4, "bits": 16, "size": 1, "varid": 9}
    lhs = CDirtyExpression(SimpleNamespace(**original), codegen=codegen)
    same = CDirtyExpression(SimpleNamespace(**(original | {"varid": 10})), codegen=codegen)
    different = CDirtyExpression(SimpleNamespace(**(original | {"bits": 8})), codegen=codegen)
    assert _same_c_expression_8616(lhs, same)
    assert not _same_c_expression_8616(lhs, different)


def test_unknown_dirty_expression_requires_payload_identity():
    codegen = _DummyCodegen()
    payload = object()
    lhs = CDirtyExpression(payload, codegen=codegen)
    same = CDirtyExpression(payload, codegen=codegen)
    different = CDirtyExpression(object(), codegen=codegen)
    assert _same_c_expression_8616(lhs, same)
    assert not _same_c_expression_8616(lhs, different)


def test_cycle_detection_does_not_confuse_shared_subtrees_with_cycles():
    codegen = _DummyCodegen()
    shared = CConstant(1, SimTypeShort(False), codegen=codegen)
    root = CBinaryOp("Or", shared, shared, codegen=codegen)
    assert not _c_ast_cycle_path_8616(root)
    assert not _c_ast_cycle_path_8616(root, max_nodes=0)
