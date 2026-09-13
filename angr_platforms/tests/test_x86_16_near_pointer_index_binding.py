"""Keep pointer-carrier identity distinct from an unscaled byte index."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CIndexedVariable,
    CUnaryOp,
    CVariable,
)
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.lowering.authoritative_function_prototypes import (
    authoritative_function_prototype_8616,
    publish_authoritative_function_prototype_8616,
)
from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_expr_8616
from angr_platforms.X86_16.lowering.near_pointer_argument import NearPointerArgumentFact8616
from angr_platforms.X86_16.lowering.segmented_memory_lowering import lower_runtime_segment_access_8616
from test_x86_16_segmented_runtime_lowering import _project, _seg_linear


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(("carrier_name", "exact", "delta"), [
    ("si", True, 0), ("si", False, 0), (None, False, 0),
    ("di", True, 0), ("si", True, 1),
])
def test_byte_index_binding_uses_proven_carrier_not_first_variable(reverse, carrier_name, exact, delta):
    project, codegen = _project()
    word = SimTypeShort(False).with_arch(project.arch)
    pointer = CVariable(
        SimStackVariable(6, 2, base="bp", name="buffer", region=0x4010),
        variable_type=word, codegen=codegen,
    )
    index = CVariable(
        SimRegisterVariable(*project.arch.registers["bx"], name="index"),
        variable_type=word, codegen=codegen,
    )
    carrier = runtime_gp_state_expr_8616("si", codegen=codegen, function_addr=0x4010)
    assert carrier is not None
    codegen.cfunc.arg_list = [pointer]
    codegen.cfunc.functy = SimTypeFunction([word], word).with_arch(project.arch)
    publish_authoritative_function_prototype_8616(
        project, codegen.cfunc.addr, codegen.cfunc.functy, source=PrototypeSource.CCA_DECOMPILER,
    )
    codegen._inertia_near_pointer_argument_facts_8616 = (
        NearPointerArgumentFact8616(
            6, 0x4014, 0x4018, 1, source_version_delta=delta,
            carrier_register_name=carrier_name, carrier_value_is_exact=exact,
        ),
    )
    codegen._inertia_near_pointer_argument_classified_offsets_8616 = set()
    codegen._inertia_near_pointer_argument_materialized_offsets_8616 = set()
    lhs, rhs = (carrier, index) if reverse else (index, carrier)
    offset = CBinaryOp("Add", lhs, rhs, codegen=codegen)
    operand = _seg_linear(project, "ds", offset, codegen)
    operand._type = SimTypePointer(SimTypeChar(False)).with_arch(project.arch)
    access = CUnaryOp("Dereference", operand, codegen=codegen, tags={"ins_addr": 0x4018})

    result = lower_runtime_segment_access_8616(access, target="portable-flat")

    if carrier_name != "si" or not exact or delta:
        assert not isinstance(result, CIndexedVariable)
        assert pointer.variable_type is word
        return
    assert isinstance(result, CIndexedVariable)
    assert result.variable is pointer
    assert result.index is index
    assert isinstance(pointer.variable_type.pts_to, SimTypeChar)
    published = authoritative_function_prototype_8616(project, codegen.cfunc, argument_count=1)
    assert isinstance(published.args[0], SimTypePointer)
    assert isinstance(published.args[0].pts_to, SimTypeChar)
