"""Legacy cleanup must preserve expression identity and required conversions."""

import builtins
import subprocess
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_simplify import _simplify_structured_expressions_8616
from angr_platforms.X86_16.lowering.condition_stack_operands import project_contained_stack_integer_view_8616
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint
from angr_platforms.X86_16.validation_condition_precision import condition_precision_token_8616

from inertia_decompiler import cli_c_ast_rewrites as rewrites


class _Codegen:
    def __init__(self):
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc: SimpleNamespace = SimpleNamespace()
        self.cstyle_null_cmp = False
        self.stmt_comments = {}
        self.expr_comments = {}
        self.const_formats = {}
        self.display_vvar_ids = False
        self._index = 0

    def next_node_idx(self):
        self._index += 1
        return self._index

    def next_idx(self, _name):
        return self.next_node_idx()

    def next_ident(self, name):
        return name


@pytest.mark.parametrize("byte_delta", [0, 1])
@pytest.mark.parametrize("extra_mask", [False, True])
def test_bitwise_cleanup_preserves_proven_stack_byte_view(byte_delta, extra_mask):
    """Flattening must not erase the owner/view proof of a retained byte read."""
    codegen = _Codegen()
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    owner = c.CVariable(SimStackVariable(-8, 2, base="bp", name="value"),
                        variable_type=word, codegen=codegen)
    expression = project_contained_stack_integer_view_8616(
        codegen, owner, owner_bp_offset=-8, offset=-8 + byte_delta,
        size=1, signed=False, tags=None,
    )
    if extra_mask:
        expression = c.CBinaryOp("And", expression, c.CConstant(0xFF, word, codegen=codegen), codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=c.CReturn(expression, codegen=codegen),
                                   arg_list=(), variables_in_use={}, unified_local_vars={})
    before = condition_precision_token_8616(_expr_fingerprint(expression, codegen.project))

    rewrites._simplify_structured_c_expressions(codegen)

    result = codegen.cfunc.statements.retval
    after = condition_precision_token_8616(_expr_fingerprint(result, codegen.project))
    assert before == f"stack_slot:SS:BP{-8 + byte_delta:+#x}:size1"
    assert after == before


@pytest.mark.parametrize("space", ["stack", "memory"])
def test_byte_join_cleanup_cannot_create_unbound_word_storage(tmp_path, space):
    """Adjacent physical bytes do not establish a new C object's definition."""
    codegen = _Codegen()
    byte = SimTypeChar(False).with_arch(codegen.project.arch)
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    variables = (
        [SimStackVariable(-8 + index, 1, base="bp", name=name, region=0x1000)
         for index, name in enumerate(("lo", "hi"))]
        if space == "stack" else
        [SimMemoryVariable(0x2000 + index, 1, name=name)
         for index, name in enumerate(("lo", "hi"))]
    )
    lo, hi = [c.CVariable(variable, variable_type=byte, codegen=codegen) for variable in variables]
    joined = c.CBinaryOp(
        "Or", lo, c.CBinaryOp("Shl", hi, c.CConstant(8, word, codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=joined, body=joined)
    _simplify_structured_expressions_8616(codegen)
    expression = codegen.cfunc.statements.c_repr()
    source = (
        f"unsigned f(unsigned char lo, unsigned char hi) {{ return {expression}; }}\n"
        "int main(void) { return f(0xff, 0x80) != 0x80ff || f(0x34, 0x12) != 0x1234; }\n"
    )
    executable = tmp_path / "join"
    compiled = subprocess.run(
        ["gcc", "-x", "c", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(executable), "-"],
        input=source, capture_output=True, text=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr + source
    assert subprocess.run([str(executable)], check=False).returncode == 0


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


@pytest.mark.parametrize("storage", ["register", "stack", "global"])
def test_copy_propagation_retains_semantic_cast_class_and_metadata(storage):
    codegen = _Codegen()
    instruction_address = 0x1200
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    signed_word = SimTypeShort(True).with_arch(codegen.project.arch)
    source_variable = {
        "register": SimRegisterVariable(4, 2, name="source"),
        "stack": SimStackVariable(-8, 2, base="bp", name="source"),
        "global": SimMemoryVariable(0x2000, 2, name="source"),
    }[storage]
    source = c.CVariable(source_variable, variable_type=word, codegen=codegen)
    temporary = c.CVariable(SimRegisterVariable(0, 2, name="v1"),
                           variable_type=word, codegen=codegen)
    converted = CSemanticCast8616(word, signed_word, temporary, codegen=codegen,
                                 tags={"ins_addr": instruction_address})
    condition = c.CBinaryOp("CmpGT", converted, c.CConstant(0, signed_word, codegen=codegen),
                            codegen=codegen)
    returned = c.CReturn(condition, codegen=codegen)
    capture = c.CAssignment(temporary, source, codegen=codegen)
    body = [capture]
    if storage != "register":
        # Reloading after this write would change the captured comparison value.
        body.append(c.CAssignment(source, c.CConstant(0, word, codegen=codegen), codegen=codegen))
    body.append(returned)
    statements = c.CStatements(body, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=statements, arg_list=(),
                                   variables_in_use={}, unified_local_vars={})

    rewrites._simplify_structured_c_expressions(codegen)

    result = returned.retval.lhs
    assert isinstance(result, CSemanticCast8616)
    assert isinstance(result.expr, c.CVariable)
    expected_variable = source.variable if storage == "register" else temporary.variable
    assert result.expr.variable is expected_variable
    if storage != "register":
        assert statements.statements[0] is capture
        assert capture.rhs.variable is source.variable
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
