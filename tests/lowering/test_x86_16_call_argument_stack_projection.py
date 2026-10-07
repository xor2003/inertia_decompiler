from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeFixedSizeArray, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from inertia.ir.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
    StackFrameSlot,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.postprocess.decompiler_postprocess_calls import (
    _materialize_callsite_stack_arguments_8616,
)
from inertia.lowering.call_argument_stack_sources import (
    call_argument_source_requires_exact_address_identity_8616,
    materialize_call_argument_stack_cvariable_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
)


def _codegen() -> SimpleNamespace:
    project = SimpleNamespace(arch=Arch86_16())
    return SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        cfunc=SimpleNamespace(
            addr=0x106C8,
            arg_list=(),
            statements=None,
            variables_in_use={},
            unified_local_vars={},
        ),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )


def _proven_frame(delta: int, *, bp_offset: int, size: int) -> FrameAccessArtifact:
    return FrameAccessArtifact(
        slots=(StackFrameSlot("bp", bp_offset, "local", size),),
        bp_coordinate=BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN,
            bp_entry_sp_delta=delta,
            detail="test frame proof",
            stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
        ),
    )


def test_call_argument_address_reuses_projected_byte_owner() -> None:
    codegen = _codegen()
    variable = SimStackVariable(-0x2E, 44, base="bp", name="local_2c")
    cvar = CVariable(
        variable,
        variable_type=SimTypeFixedSizeArray(SimTypeChar(False), 44).with_arch(
            codegen.project.arch
        ),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[variable] = cvar
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=-0x2C,
        entry_sp_offset=-0x2E,
        size=44,
    )
    synthetic: dict[int, CVariable] = {}

    selected = materialize_call_argument_stack_cvariable_8616(
        codegen,
        synthetic,
        machine_bp_offset=-0x2C,
        size_hint=1,
    )

    assert selected is cvar
    assert synthetic[-0x2C] is cvar


def test_call_argument_address_materializes_at_proven_entry_sp_coordinate() -> None:
    codegen = _codegen()
    codegen._inertia_vex_ir_frame = _proven_frame(-2, bp_offset=-0x2C, size=1)
    synthetic: dict[int, CVariable] = {}

    selected = materialize_call_argument_stack_cvariable_8616(
        codegen,
        synthetic,
        machine_bp_offset=-0x2C,
        size_hint=1,
        preferred_name="local_2c",
    )

    assert isinstance(selected, CVariable)
    assert isinstance(selected.variable, SimStackVariable)
    assert selected.variable.offset == -0x2E
    assert selected.variable.size == 1
    assert machine_bp_offset_for_stack_variable_8616(codegen, selected.variable) == -0x2C
    assert synthetic[-0x2C] is selected


def test_call_argument_address_refuses_unproven_coordinate_projection() -> None:
    codegen = _codegen()
    synthetic: dict[int, CVariable] = {}

    selected = materialize_call_argument_stack_cvariable_8616(
        codegen,
        synthetic,
        machine_bp_offset=-0x2C,
        size_hint=1,
    )

    assert selected is None
    assert synthetic == {}
    assert codegen.cfunc.variables_in_use == {}


def test_exact_stack_address_source_classification_is_typed() -> None:
    assert call_argument_source_requires_exact_address_identity_8616(
        ("bp_addr", -0x2C)
    )
    assert call_argument_source_requires_exact_address_identity_8616(
        ("bp_index_addr", -0x2C, "si", 1)
    )
    assert not call_argument_source_requires_exact_address_identity_8616(("bp", -0x2C))
    assert not call_argument_source_requires_exact_address_identity_8616(("unknown", -0x2C))


def test_call_argument_replay_prefers_exact_address_source_over_scalar_low_byte() -> None:
    codegen = _codegen()
    array_variable = SimStackVariable(-0x2E, 44, base="bp", name="local_2c")
    array_cvar = CVariable(
        array_variable,
        variable_type=SimTypeFixedSizeArray(SimTypeChar(False), 44).with_arch(
            codegen.project.arch
        ),
        codegen=codegen,
    )
    scalar_variable = SimStackVariable(-0x30, 2, base="bp", name="local_2e")
    scalar_cvar = CVariable(
        scalar_variable,
        variable_type=SimTypeShort(False).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    global_variable = SimMemoryVariable(0x0B4C, 2, name="g_0B4C")
    global_cvar = CVariable(
        global_variable,
        variable_type=SimTypeShort(False).with_arch(codegen.project.arch),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {
        array_variable: array_cvar,
        scalar_variable: scalar_cvar,
        global_variable: global_cvar,
    }
    codegen.cfunc.unified_local_vars = {
        array_variable: {(array_cvar, array_cvar.variable_type)},
        scalar_variable: {(scalar_cvar, scalar_cvar.variable_type)},
    }
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=array_variable,
        cvar=array_cvar,
        bp_offset=-0x2C,
        entry_sp_offset=-0x2E,
        size=44,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=scalar_variable,
        cvar=scalar_cvar,
        bp_offset=-0x2E,
        entry_sp_offset=-0x30,
        size=2,
    )
    stale_low_byte = CBinaryOp(
        "And",
        scalar_cvar,
        CConstant(0xFF, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall(
        "sub_113d4",
        SimpleNamespace(addr=0x113D4, name="sub_113d4", block_addrs_set={0x113D4}),
        [stale_low_byte, global_cvar],
        codegen=codegen,
    )
    root = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x106C8,
        codegen=codegen,
    )
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x106E6,
            target_addr=0x113D4,
            return_addr=0x106E9,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("global", 0x0B4C, 2), ("bp_addr", -0x2C)),
        ),
    }

    assert _materialize_callsite_stack_arguments_8616(codegen.project, codegen) is True

    final_call = codegen.cfunc.statements.statements[0].expr
    assert isinstance(final_call.args[0], CUnaryOp)
    assert final_call.args[0].op == "Reference"
    operand = final_call.args[0].operand
    assert isinstance(operand, CVariable)
    assert isinstance(operand.variable, SimStackVariable)
    assert machine_bp_offset_for_stack_variable_8616(codegen, operand.variable) == -0x2C
    assert operand.variable.name == "local_2c"
