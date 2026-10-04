from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CStatements, CTypeCast, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.c_ast_utils import _structured_slot_names_for_type_8616
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616

from inertia_decompiler import cli_c_ast_rewrites as cli_ast
from inertia_decompiler.cli_c_ast_rewrites import (
    _get_or_seed_inertia_alias_state,
    _simplify_basic_algebraic_identities,
    _simplify_structured_c_expressions,
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


class _FakeStore:
    __module__ = "angr.analyses.decompiler.structured_codegen.fake"

    def __init__(self, *, addr, data, codegen):
        self.addr = addr
        self.data = data
        self.codegen = codegen


def _codegen(statements):
    codegen = _DummyCodegen()
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(name: str, codegen):
    reg_offset, reg_size = codegen.project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def test_simplify_basic_algebraic_identities_rewrites_store_data_children():
    codegen = _codegen([])
    ax = _reg("ax", codegen)
    store = _FakeStore(
        addr=_const(0x2000, codegen),
        data=CBinaryOp("Xor", ax, ax, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([store], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _simplify_basic_algebraic_identities(codegen)

    assert changed is True
    assert isinstance(store.data, CConstant)
    assert store.data.value == 0


def test_get_or_seed_inertia_alias_state_tolerates_slotted_cfunc():
    codegen = _DummyCodegen()
    ax = _reg("ax", codegen)

    class _SlottedCFunc:
        __slots__ = ("addr", "body", "statements", "variables_in_use")

        def __init__(self):
            self.addr = 0x4010
            self.statements = CStatements([], addr=0x4010, codegen=codegen)
            self.body = self.statements
            self.variables_in_use = {ax.variable: ax}

    codegen.cfunc = _SlottedCFunc()

    alias_state = _get_or_seed_inertia_alias_state(codegen)

    assert alias_state is not None
    assert getattr(codegen, "_inertia_alias_state", None) is alias_state


def test_expression_operand_cleanup_preserves_condition_ownership():
    """Reconstructing a predicate must retain its Structuring provenance."""
    codegen = _codegen([])
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    ax = _reg("ax", codegen)
    tags = {
        "ins_addr": 0x4012,
        "vex_block_addr": 0x4010,
        "inertia_structuring_condition_cfg_materialized_8616": True,
    }
    predicate = CBinaryOp(
        "CmpLT", CTypeCast(word, word, ax, codegen=codegen),
        _const(7, codegen), tags=tags, codegen=codegen,
    )
    codegen.cfunc.statements.statements = [predicate]

    assert _simplify_structured_c_expressions(codegen)

    replacement = codegen.cfunc.statements.statements[0]
    assert replacement is not predicate
    assert replacement.op == predicate.op
    assert replacement.lhs is ax
    assert replacement.rhs is predicate.rhs
    assert replacement.tags == tags


def test_cli_walk_bypasses_container_scan_for_direct_and_scalar_fields(monkeypatch):
    """The measured hot path must not allocate a container walk for each field."""
    codegen = _DummyCodegen()
    lhs, rhs = _const(1, codegen), _const(2, codegen)
    root = CBinaryOp("Add", lhs, rhs, codegen=codegen)
    original = cli_ast._iter_c_node_children_8616

    def checked(value, seen_values=None):
        assert not cli_ast._structured_codegen_node(value)
        assert type(value) not in (str, bytes, int, float, complex, bool, type(None))
        return original(value, seen_values)

    monkeypatch.setattr(cli_ast, "_iter_c_node_children_8616", checked)
    assert tuple(cli_ast._iter_c_nodes_deep(root)) == (root, rhs, lhs)


def test_cli_slot_cache_retains_inheritance_exclusions_and_instance_mutations():
    """Cache class metadata only; dictionaries and slot values remain live."""
    class Base:
        __module__ = "angr.analyses.decompiler.structured_codegen.fake"
        __slots__ = ("__dict__", "child", "codegen", "idx", "tags")

    class Extension(Base):
        __module__ = "angr.analyses.decompiler.structured_codegen.fake"
        __slots__ = "extra"

    root, other = Extension(), Extension()
    codegen = _DummyCodegen()
    first, second, third = (_const(n, codegen) for n in range(3))
    root.child, root.extra = first, second
    root.codegen, root.idx, root.tags = third, 1, {}
    root.dynamic = third
    expected = ("extra", "child", "idx", "tags", "dynamic")
    _structured_slot_names_for_type_8616.cache_clear()
    assert cli_ast._structured_slot_names_8616(root) == expected
    cached = _structured_slot_names_for_type_8616.cache_info()
    assert cli_ast._structured_slot_names_8616(other) == expected[:-1]
    assert _structured_slot_names_for_type_8616.cache_info().hits == cached.hits + 1
    assert _structured_slot_names_for_type_8616(Extension) == ("extra", "child")
    assert tuple(cli_ast._iter_c_nodes_deep(root)) == (root, third, first, second)
    del root.dynamic
    root.child = third
    assert tuple(cli_ast._iter_c_nodes_deep(root)) == (root, third, second)


@pytest.mark.parametrize("container", [list, tuple, set, lambda values: dict(enumerate(values))])
def test_cli_walk_containers_preserve_children_and_shared_identity(container):
    codegen = _DummyCodegen()
    first, second = _const(1, codegen), _const(2, codegen)
    root = _FakeStore(addr=first, data=container([first, second]), codegen=codegen)
    nodes = tuple(cli_ast._iter_c_nodes_deep(root))
    assert nodes[0] is root
    assert {id(node) for node in nodes} == {id(root), id(first), id(second)}
    assert len(nodes) == 3


def test_cli_walk_generic_iterable_cycles_and_deep_chain():
    class Children:
        def __init__(self, values):
            self.values = values

        def __iter__(self):
            return iter(self.values)

    codegen = _DummyCodegen()
    leaf = _const(1, codegen)
    cycle = []
    cycle.extend([cycle, leaf])
    root = _FakeStore(addr=None, data=Children([cycle]), codegen=codegen)
    root.loop = root
    assert tuple(cli_ast._iter_c_nodes_deep(root)) == (root, leaf)
    chain = [root]
    for _ in range(1200):
        chain.append(_FakeStore(addr=None, data=chain[-1], codegen=codegen))
    assert tuple(cli_ast._iter_c_nodes_deep(chain[-1])) == (*reversed(chain), leaf)


def test_cli_walk_semantic_cast_and_inherited_constant_children():
    class ExtendedConstant(CConstant):
        __slots__ = ("extra",)

    codegen = _DummyCodegen()
    child = _const(7, codegen)
    extended = ExtendedConstant(1, SimTypeShort(False), codegen=codegen)
    extended.extra = child
    root = CSemanticCast8616(SimTypeShort(False), SimTypeShort(True), extended, codegen=codegen)
    assert tuple(cli_ast._iter_c_nodes_deep(root)) == (root, extended, child)


def test_cli_walk_keeps_unexpected_descriptor_failures_loud():
    class Broken:
        __module__ = "angr.analyses.decompiler.structured_codegen.fake"
        __slots__ = ("child",)

        def __getattribute__(self, name):
            if name == "child":
                raise RuntimeError("broken child descriptor")
            return object.__getattribute__(self, name)

    with pytest.raises(RuntimeError, match="broken child descriptor"):
        tuple(cli_ast._iter_c_nodes_deep(Broken()))
