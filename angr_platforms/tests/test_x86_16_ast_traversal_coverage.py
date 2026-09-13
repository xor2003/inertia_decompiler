"""Read and mutation walkers must honor the same declared child schema."""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr_platforms.X86_16 import c_ast_utils as ast

CODEGEN = SimpleNamespace(next_ident=lambda name: name, next_node_idx=count().__next__)


@pytest.mark.parametrize("name,field", [
    (name, field)
    for name, fields in ast._STRUCTURED_CHILD_ATTRS_BY_CLASS_8616.items()
    for field in fields
])
@pytest.mark.parametrize("container", ["scalar", "list", "tuple", "dict"])
def test_every_declared_child_is_read_and_replaced(name, field, container):
    fields = ast._STRUCTURED_CHILD_ATTRS_BY_CLASS_8616[name]
    boundary_type = type(name, (), {"__module__": c.__name__, "__slots__": fields})
    root = boundary_type()
    for attribute in fields:
        setattr(root, attribute, None)
    marker = c.CStatements([], codegen=CODEGEN)
    replacement = c.CStatements([], codegen=CODEGEN)
    wrapped = {"scalar": marker, "list": [marker], "tuple": (marker,), "dict": {0: marker}}[container]
    setattr(root, field, wrapped)
    assert marker in list(ast._iter_c_nodes_deep_8616(root))
    assert ast._replace_c_children_8616(root, lambda node: replacement if node is marker else node)
    visited = list(ast._iter_c_nodes_deep_8616(root))
    assert replacement in visited
    assert marker not in visited


@pytest.mark.parametrize("container", ["scalar", "list", "tuple", "dict"])
def test_child_policy_preserves_refused_edge(container):
    marker = c.CStatements([], codegen=CODEGEN)
    wrapped = {"scalar": marker, "list": [marker], "tuple": (marker,), "dict": {0: marker}}[container]
    root = c.CReturn(wrapped, codegen=CODEGEN)
    replacement = c.CStatements([], codegen=CODEGEN)
    assert not ast._replace_c_children_8616(
        root, lambda node: replacement if node is marker else node,
        should_process_child=lambda _parent, _field: False,
    )
    assert marker in list(ast._iter_c_nodes_deep_8616(root))


def test_cyclic_container_reports_node_and_child_path():
    children = []
    children.append(children)
    root = c.CReturn(children, codegen=CODEGEN)
    with pytest.raises(ast.CTraversalContractError8616) as caught:
        ast._replace_c_children_8616(root, lambda node: node)
    assert caught.value.reason is ast.CTraversalFailure8616.CONTAINER_CYCLE
    assert caught.value.node_type == "CReturn"
    assert caught.value.child_path == "retval[0]"


@pytest.mark.parametrize("failure", ["read", "write"])
def test_broken_child_access_reports_its_field(failure):
    marker = c.CStatements([], codegen=CODEGEN)

    def read(_self):
        if failure == "read":
            raise ValueError("invalid child storage")
        return marker

    node_type = type("CReturn", (), {"__module__": c.__name__, "retval": property(read)})
    with pytest.raises(ast.CTraversalContractError8616) as caught:
        ast._replace_c_children_8616(node_type(), lambda _node: c.CStatements([], codegen=CODEGEN))
    assert caught.value.node_type == "CReturn"
    assert caught.value.child_path == "retval"
    assert caught.value.reason is (
        ast.CTraversalFailure8616.CHILD_READ if failure == "read" else ast.CTraversalFailure8616.CHILD_WRITE
    )
