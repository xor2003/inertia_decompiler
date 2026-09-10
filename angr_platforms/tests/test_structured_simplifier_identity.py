"""Temporary expression identities must not substitute unrelated arithmetic."""

import builtins
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16

from inertia_decompiler import cli_c_ast_rewrites as rewrites


class _Codegen:
    def __init__(self):
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc: SimpleNamespace = SimpleNamespace()
        self.cstyle_null_cmp = False
        self.stmt_comments = {}
        self.expr_comments = {}
        self.display_vvar_ids = False
        self._index = 0

    def next_node_idx(self):
        self._index += 1
        return self._index

    def next_idx(self, _name):
        return self.next_node_idx()

    def next_ident(self, name):
        return name


def test_simplifier_does_not_reuse_another_expression_analysis(monkeypatch):
    codegen = _Codegen()
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    variables = [c.CVariable(SimStackVariable(offset, 2, base="bp", name=name),
                            variable_type=word, codegen=codegen)
                 for offset, name in ((4, "first"), (6, "second"), (8, "third"))]
    first, second, third = variables
    address = c.CBinaryOp("Add", first, c.CConstant(7, word, codegen=codegen), codegen=codegen)
    difference = c.CBinaryOp("Sub", second, third, codegen=codegen)
    condition = c.CBinaryOp("CmpLT", address, difference, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=c.CReturn(condition, codegen=codegen),
                                   arg_list=(), variables_in_use={}, unified_local_vars={})
    # Model allocator reuse deterministically instead of depending on GC timing.
    monkeypatch.setattr(rewrites, "id", lambda node: 1 if isinstance(node, c.CBinaryOp)
                        else builtins.id(node), raising=False)
    # A valid identity analysis lets this test isolate memoization from matching.
    monkeypatch.setattr(rewrites, "_analyze_widening_expr", lambda node, *_callbacks:
                        SimpleNamespace(kind="linear", base_expr=node, delta=0))

    rewrites._simplify_structured_c_expressions(codegen)

    result = codegen.cfunc.statements.retval.rhs
    assert result.op == "Sub"
    assert result.lhs.variable is second.variable
    assert result.rhs.variable is third.variable
