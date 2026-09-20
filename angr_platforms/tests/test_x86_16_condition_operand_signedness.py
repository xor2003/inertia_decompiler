"""Typed branch ordering must survive unsigned C storage declarations."""

import subprocess
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.structuring import condition_materialization as owner


@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize("refine_declaration", [False, True])
@pytest.mark.parametrize("variable_on_left", [False, True])
@pytest.mark.parametrize(("width", "type_class", "scale"), [(16, SimTypeShort, 1), (32, SimTypeLong, 65537)])
def test_condition_materialization_preserves_ordering_over_opposite_storage(
    monkeypatch, signed, refine_declaration, variable_on_left, width, type_class, scale, tmp_path,
):
    """Operand signedness is a view, not permission to mutate shared storage."""
    arch = Arch86_16()
    codegen = SimpleNamespace(
        next_node_idx=lambda: 1, next_ident=lambda name: name,
        project=SimpleNamespace(arch=arch), show_casts=False, display_vvar_ids=False,
        cstyle_null_cmp=False, const_formats={},
    )
    storage_type = type_class(signed if refine_declaration else not signed).with_arch(arch)
    variable = c.CVariable(
        SimMemoryVariable(0x200, width // 8, name="value"),
        variable_type=storage_type, codegen=codegen,
    )
    constant = c.CConstant(350, SimTypeShort(False).with_arch(arch), codegen=codegen)
    lhs, rhs = (variable, constant) if variable_on_left else (constant, variable)
    comparison = c.CBinaryOp("CmpLE", lhs, rhs, codegen=codegen)
    condition = ConditionIR(op="sle" if signed else "ule", lhs=1, rhs=350, width_bits=width)
    monkeypatch.setattr(owner._legacy_typed_conditions, "_build_c_condition_expr", lambda *a, **kw: comparison)
    result = owner.materialize_condition_ir_expression_8616(codegen.project, codegen, condition)
    assert result is comparison
    converted = result.lhs if variable_on_left else result.rhs
    assert isinstance(converted, CSemanticCast8616)
    assert converted.dst_type.signed is signed
    assert converted.expr is variable
    assert variable.variable_type is storage_type
    if refine_declaration:
        # Later declaration refinement must not erase the earlier ordering proof.
        variable.variable_type = type_class(not signed).with_arch(arch)
    rendered = "".join(text for text, _node in result.c_repr_chunks())
    storage = f"{'u' if signed else ''}int{width}_t"
    interpreted = (
        f"(bits < {1 << (width - 1)} ? (int64_t)bits : (int64_t)bits - {1 << width})"
        if signed else "bits"
    )
    expected = f"{interpreted} <= 350" if variable_on_left else f"350 <= {interpreted}"
    source = (
        "#include <stdint.h>\n"
        "int main(void) { for (unsigned int raw = 0; raw < 65536; ++raw) {"
        f"uint64_t bits = raw < 512 ? raw : (uint64_t)raw * {scale};"
        f"{storage} {variable.name} = bits;"
        f"if (({rendered}) != ({expected})) return 1;"
        "} return 0; }"
    )
    executable = tmp_path / "condition-ordering"
    compiled = subprocess.run(
        ["gcc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-O2", "-x", "c", "-", "-o", str(executable)],
        input=source, capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=5)
    assert executed.returncode == 0, executed.stderr
