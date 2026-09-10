"""Legacy cleanup must preserve expression identity and required conversions."""

import builtins
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616

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


@pytest.mark.parametrize("operation", ["CmpGT", "CmpLT", "Add", "Shr"])
def test_simplifier_preserves_required_signed_conversion(operation):
    codegen = _Codegen()
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    signed_word = SimTypeShort(True).with_arch(codegen.project.arch)
    variable = c.CVariable(SimStackVariable(-8, 2, base="bp", name="index"),
                          variable_type=word, codegen=codegen)
    converted = CSemanticCast8616(word, signed_word, variable, codegen=codegen)
    expression = c.CBinaryOp(operation, converted, c.CConstant(1, signed_word, codegen=codegen),
                             codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=c.CReturn(expression, codegen=codegen),
                                   arg_list=(), variables_in_use={}, unified_local_vars={})

    rewrites._simplify_structured_c_expressions(codegen)

    result = codegen.cfunc.statements.retval.lhs
    assert isinstance(result, CSemanticCast8616)
    assert isinstance(result.src_type, SimTypeShort)
    assert isinstance(result.dst_type, SimTypeShort)
    assert isinstance(result.expr, c.CVariable)
    assert result.src_type.signed is False
    assert result.dst_type.signed is True
    assert result.expr.variable is variable.variable


def test_cosmetic_cast_unwrapping_stops_at_required_conversion():
    codegen = _Codegen()
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    signed_word = SimTypeShort(True).with_arch(codegen.project.arch)
    value = c.CConstant(0xFFFF, word, codegen=codegen)
    semantic = CSemanticCast8616(word, signed_word, value, codegen=codegen)
    cosmetic = c.CTypeCast(signed_word, signed_word, semantic, codegen=codegen)

    assert rewrites._unwrap_c_casts(cosmetic) is semantic
    assert rewrites._unwrap_c_casts(c.CTypeCast(word, word, value, codegen=codegen)) is value


def test_copy_propagation_retains_semantic_cast_class_and_metadata():
    codegen = _Codegen()
    instruction_address = 0x1200
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    signed_word = SimTypeShort(True).with_arch(codegen.project.arch)
    source = c.CVariable(SimStackVariable(-8, 2, base="bp", name="source"),
                        variable_type=word, codegen=codegen)
    temporary = c.CVariable(SimRegisterVariable(0, 2, name="v1"),
                           variable_type=word, codegen=codegen)
    converted = CSemanticCast8616(word, signed_word, temporary, codegen=codegen,
                                 tags={"ins_addr": instruction_address})
    condition = c.CBinaryOp("CmpGT", converted, c.CConstant(0, signed_word, codegen=codegen),
                            codegen=codegen)
    returned = c.CReturn(condition, codegen=codegen)
    statements = c.CStatements([c.CAssignment(temporary, source, codegen=codegen), returned], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=statements, arg_list=(),
                                   variables_in_use={}, unified_local_vars={})

    rewrites._simplify_structured_c_expressions(codegen)

    result = returned.retval.lhs
    assert isinstance(result, CSemanticCast8616)
    assert isinstance(result.expr, c.CVariable)
    assert result.expr.variable is source.variable
    assert result.src_type is word
    assert result.dst_type is signed_word
    assert result.tags["ins_addr"] == instruction_address


@pytest.mark.parametrize("known_declaration", [False, True])
def test_semantic_cast_elision_requires_current_declaration_proof(known_declaration):
    codegen = _Codegen()
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    variable = c.CVariable(SimStackVariable(-4, 2, base="bp", name="index"),
                          variable_type=word, codegen=codegen)
    converted = CSemanticCast8616(word, word, variable, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=(),
        unified_local_vars={variable.variable: {(variable, word)}} if known_declaration else {},
    )

    result = rewrites._unwrap_c_casts(converted)

    assert result is (variable if known_declaration else converted)
