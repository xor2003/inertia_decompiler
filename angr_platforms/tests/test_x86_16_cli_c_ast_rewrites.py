from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CStatements, CTypeCast, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16

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
