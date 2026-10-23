"""Tests for SSA-proven GP architectural runtime-state lowering."""

from __future__ import annotations

from types import SimpleNamespace

from angr.ailment import Expr
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CExpressionStatement,
    CFunctionCall,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.rustylib.ailment import VirtualVariableCategory
from angr.sim_type import SimTypeChar, SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import IRAddress, IRInstr, IRValue, MemSpace
from inertia.ir.function_ssa_registry import FunctionSSAArtifactStage8616
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.gp_register_state import (
    _register_projection_for_shape_8616,
    gp_live_in_names_from_c_ast_8616,
    gp_live_in_names_from_ssa_8616,
    lower_architectural_gp_register_state_8616,
    runtime_gp_expression_view_8616,
    runtime_gp_name_for_variable_8616,
)
from inertia.validation.tail_validation_fingerprint import _expr_fingerprint


def test_register_projection_preserves_aliases_and_refuses_conflicts() -> None:
    """Only one coherent lane may own a shape; architecture changes stay visible."""
    registers = {"ax": (8, 2), "AX": (8, 2), "ah": (9, 1), "flags": (40, 2)}
    project = SimpleNamespace(arch=SimpleNamespace(registers=registers))
    assert _register_projection_for_shape_8616(project, 8, 2) == ("eax", 0, 2)
    assert _register_projection_for_shape_8616(project, 9, 1) == ("eax", 8, 1)
    assert _register_projection_for_shape_8616(project, 8, 4) is None
    assert _register_projection_for_shape_8616(project, 40, 2) is None
    registers["bx"] = (8, 2)
    assert _register_projection_for_shape_8616(project, 8, 2) is None


def _gp_live_in_artifact(register_name: str = "di") -> SSAFunctionArtifact:
    """Build one exact GP read before a later definition of the same register."""
    offset, size = Arch86_16().registers[register_name]
    read = IRValue(MemSpace.REG, name=register_name, offset=offset, size=size)
    temp = IRValue(MemSpace.TMP, name="t0", offset=0, size=size)
    write = IRValue(MemSpace.REG, name=register_name, offset=offset, size=size)
    block = SSABlock(
        addr=0x10E85,
        instrs=(
            IRInstr("MOV", temp, (IRAddress(MemSpace.DS, base_values=(read,)),), 2, 0x10E87),
            IRInstr("MOV", write, (IRValue(MemSpace.CONST, const=0, size=size),), size, 0x10E93),
        ),
        bindings=(),
    )
    return SSAFunctionArtifact(function_addr=0x10E85, blocks=(block,), predecessor_map={0x10E85: ()})


def test_gp_live_in_names_uses_upward_exposed_ssa_read() -> None:
    """A read before the first DI definition proves architectural live-in state."""
    assert gp_live_in_names_from_ssa_8616(_gp_live_in_artifact()) == frozenset({"edi"})


def test_gp_live_in_names_supports_ax_parent_state() -> None:
    """AX uses the same typed architectural-state lane as index registers."""
    assert gp_live_in_names_from_ssa_8616(_gp_live_in_artifact("ax")) == frozenset({"eax"})


def test_gp_live_in_names_supports_eax_full_width_state() -> None:
    """An operand-size override keeps EAX as one typed 32-bit live-in lane."""
    assert gp_live_in_names_from_ssa_8616(_gp_live_in_artifact("eax")) == frozenset({"eax"})


def test_gp_live_in_names_supports_sp_parent_state() -> None:
    """A PUSH address read exposes the coherent ESP architectural live-in."""
    assert gp_live_in_names_from_ssa_8616(_gp_live_in_artifact("sp")) == frozenset({"esp"})


def test_runtime_gp_name_uses_typed_state_category() -> None:
    """Synthetic runtime addresses retain architectural register identity."""
    variable = SimMemoryVariable(
        0x10014,
        4,
        name="inertia_edi",
        category="inertia_gp_register_state",
    )

    assert runtime_gp_name_for_variable_8616(variable) == "edi"


def test_tail_fingerprint_canonicalizes_runtime_edi_low_word_as_di() -> None:
    """A coherent EDI runtime lane and architectural DI have one identity."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    edi = CVariable(
        SimMemoryVariable(
            0x10014,
            4,
            name="inertia_edi",
            category="inertia_gp_register_state",
        ),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    low_word = CBinaryOp(
        "And",
        edi,
        CConstant(0xFFFF, SimTypeLong(False), codegen=codegen),
        codegen=codegen,
    )

    assert _expr_fingerprint(low_word, project) == "reg:di"


def test_gp_runtime_state_replaces_untagged_di_carrier() -> None:
    """An exact DI carrier lowers to the low word of coherent EDI state."""
    arch = Arch86_16()
    offset, size = arch.registers["di"]
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={0x10E85: _gp_live_in_artifact()},
        _inertia_function_ssa_stages_8616={0x10E85: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    dirty = CDirtyExpression(
        Expr.VirtualVariable(1, 3, size * 8, VirtualVariableCategory.REGISTER, oident=offset),
        codegen=codegen,
    )
    root = CBinaryOp(
        "Shr",
        dirty,
        CConstant(4, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x10E85, statements=root, unified_local_vars={})

    assert lower_architectural_gp_register_state_8616(codegen) is True
    replacement = codegen.cfunc.statements.lhs
    assert isinstance(replacement, CBinaryOp)
    assert replacement.op == "And"
    assert isinstance(replacement.lhs, CVariable)
    assert isinstance(replacement.lhs.variable, SimMemoryVariable)
    assert replacement.lhs.variable.name == "inertia_edi"
    assert replacement.rhs.value == 0xFFFF
    assert codegen._inertia_gp_register_state_lowering_stats_8616.failure_count == 0


def test_gp_runtime_state_projects_addressed_bh_view_before_inner_bx_rewrite() -> None:
    """Angr's pointer-shaped BH alias lowers as a value, not address arithmetic."""
    arch = Arch86_16()
    bx_offset, bx_size = arch.registers["bx"]
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={},
        _inertia_function_ssa_stages_8616={},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    bx = CVariable(
        SimRegisterVariable(bx_offset, bx_size, ident="bx_live", region=0x1AF_CF),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    addressed_bh = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CUnaryOp("Reference", bx, codegen=codegen),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1AF_CF,
        statements=addressed_bh,
        unified_local_vars={},
    )

    assert lower_architectural_gp_register_state_8616(codegen) is True
    replacement = codegen.cfunc.statements
    view = runtime_gp_expression_view_8616(replacement)
    assert view is not None
    assert view.register_name == "bh"


def test_gp_runtime_state_projects_addressed_ah_from_full_eax_carrier() -> None:
    """Angr may address AH as byte one of the full 32-bit EAX carrier."""
    artifact = _gp_live_in_artifact("eax")
    project = SimpleNamespace(
        arch=Arch86_16(),
        _inertia_function_ssa_artifacts_8616={artifact.function_addr: artifact},
        _inertia_function_ssa_stages_8616={
            artifact.function_addr: FunctionSSAArtifactStage8616.IR,
        },
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    eax_offset, eax_size = project.arch.registers["eax"]
    eax = CVariable(
        SimRegisterVariable(
            eax_offset,
            eax_size,
            ident="eax_live",
            region=artifact.function_addr,
        ),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=artifact.function_addr,
        statements=CUnaryOp(
            "Dereference",
            CBinaryOp(
                "Add",
                CUnaryOp("Reference", eax, codegen=codegen),
                CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        unified_local_vars={},
    )

    assert lower_architectural_gp_register_state_8616(codegen) is True
    view = runtime_gp_expression_view_8616(codegen.cfunc.statements)
    assert view is not None
    assert view.register_name == "ah"


def test_gp_runtime_state_projects_addressed_ah_from_owned_eax_lane() -> None:
    """Late cleanup replay recognizes byte one of an owned runtime EAX lane."""
    project = SimpleNamespace(
        arch=Arch86_16(),
        _inertia_function_ssa_artifacts_8616={},
        _inertia_function_ssa_stages_8616={},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    runtime_eax = CVariable(
        SimMemoryVariable(
            0x10000,
            4,
            name="inertia_eax",
            category="inertia_gp_register_state",
        ),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x18C19,
        statements=CUnaryOp(
            "Dereference",
            CBinaryOp(
                "Add",
                CUnaryOp("Reference", runtime_eax, codegen=codegen),
                CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        unified_local_vars={},
    )

    assert lower_architectural_gp_register_state_8616(codegen) is True
    view = runtime_gp_expression_view_8616(codegen.cfunc.statements)
    assert view is not None
    assert view.register_name == "ah"


def test_gp_runtime_state_projects_addressed_bh_after_inner_bx_rewrite() -> None:
    """A replayed pointer-shaped BH alias recognizes the existing runtime BX view."""
    artifact = _gp_live_in_artifact("bx")
    project = SimpleNamespace(
        arch=Arch86_16(),
        _inertia_function_ssa_artifacts_8616={artifact.function_addr: artifact},
        _inertia_function_ssa_stages_8616={
            artifact.function_addr: FunctionSSAArtifactStage8616.IR,
        },
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    runtime_ebx = CVariable(
        SimMemoryVariable(
            0x1000C,
            4,
            name="inertia_ebx",
            category="inertia_gp_register_state",
        ),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    runtime_bx = CBinaryOp(
        "And",
        runtime_ebx,
        CConstant(0xFFFF, SimTypeLong(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=artifact.function_addr,
        statements=CUnaryOp(
            "Dereference",
            CBinaryOp(
                "Add",
                CUnaryOp("Reference", runtime_bx, codegen=codegen),
                CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        unified_local_vars={},
    )

    assert lower_architectural_gp_register_state_8616(codegen) is True
    view = runtime_gp_expression_view_8616(codegen.cfunc.statements)
    assert view is not None
    assert view.register_name == "bh"


def test_gp_runtime_state_projects_casted_addressed_bh_view() -> None:
    """Casts used by angr to render BH do not turn the byte view into a pointer."""
    artifact = _gp_live_in_artifact("bx")
    project = SimpleNamespace(
        arch=Arch86_16(),
        _inertia_function_ssa_artifacts_8616={artifact.function_addr: artifact},
        _inertia_function_ssa_stages_8616={artifact.function_addr: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    bx_offset, bx_size = project.arch.registers["bx"]
    bx = CVariable(
        SimRegisterVariable(bx_offset, bx_size, ident="bx_3", region=artifact.function_addr),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    reference = CTypeCast(
        None,
        SimTypeLong(False),
        CUnaryOp("Reference", bx, codegen=codegen),
        codegen=codegen,
    )
    address = CTypeCast(
        None,
        SimTypeLong(False),
        CBinaryOp(
            "Add",
            reference,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=artifact.function_addr,
        statements=CUnaryOp("Dereference", address, codegen=codegen),
        unified_local_vars={},
    )

    assert lower_architectural_gp_register_state_8616(codegen) is True
    view = runtime_gp_expression_view_8616(codegen.cfunc.statements)
    assert view is not None
    assert view.register_name == "bh"


def test_gp_runtime_state_reconciles_late_raw_bh_with_owned_ebx_lane() -> None:
    """An existing runtime EBX lane owns later raw SSA subviews on replay."""
    project = SimpleNamespace(
        arch=Arch86_16(),
        _inertia_function_ssa_artifacts_8616={},
        _inertia_function_ssa_stages_8616={},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    runtime_ebx = CVariable(
        SimMemoryVariable(
            0x1000C,
            4,
            name="inertia_ebx",
            category="inertia_gp_register_state",
        ),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    bx_offset, bx_size = project.arch.registers["bx"]
    bx = CVariable(
        SimRegisterVariable(bx_offset, bx_size, ident="bx_3", region=0x1AF_CF),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    casted_bh = CUnaryOp(
        "Dereference",
        CTypeCast(
            None,
            SimTypeLong(False),
            CBinaryOp(
                "Add",
                CTypeCast(
                    None,
                    SimTypeLong(False),
                    CUnaryOp("Reference", bx, codegen=codegen),
                    codegen=codegen,
                ),
                CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1AF_CF,
        statements=CStatements(
            [
                CAssignment(
                    runtime_ebx,
                    CConstant(0, SimTypeLong(False), codegen=codegen),
                    codegen=codegen,
                ),
                CAssignment(
                    bx,
                    CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                CReturn(casted_bh, codegen=codegen),
            ],
            codegen=codegen,
        ),
        unified_local_vars={},
    )

    assert gp_live_in_names_from_c_ast_8616(codegen.cfunc.statements, project) == frozenset()
    assert lower_architectural_gp_register_state_8616(codegen) is True
    view = runtime_gp_expression_view_8616(codegen.cfunc.statements.statements[-1].retval)
    assert view is not None
    assert view.register_name == "bh"


def test_gp_runtime_state_projects_al_from_coherent_ax_parent() -> None:
    """An AL live-in reads the low byte of AX runtime state, never separate storage."""
    arch = Arch86_16()
    al_offset, al_size = arch.registers["al"]
    read = IRValue(MemSpace.REG, name="al", offset=al_offset, size=al_size)
    block = SSABlock(
        addr=0x1241E,
        instrs=(
            IRInstr(
                "MOV",
                IRValue(MemSpace.TMP, name="t0", size=1),
                (read,),
                1,
                0x12431,
            ),
        ),
        bindings=(),
    )
    artifact = SSAFunctionArtifact(
        function_addr=0x1241E,
        blocks=(block,),
        predecessor_map={0x1241E: ()},
    )
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={0x1241E: artifact},
        _inertia_function_ssa_stages_8616={0x1241E: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    dirty = CDirtyExpression(
        Expr.VirtualVariable(
            1,
            3,
            al_size * 8,
            VirtualVariableCategory.REGISTER,
            oident=al_offset,
        ),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x1241E, statements=dirty, unified_local_vars={})

    assert lower_architectural_gp_register_state_8616(codegen) is True
    replacement = codegen.cfunc.statements
    assert isinstance(replacement, CBinaryOp)
    assert replacement.op == "And"
    assert isinstance(replacement.lhs, CVariable)
    assert replacement.lhs.variable.name == "inertia_eax"
    assert replacement.rhs.value == 0xFF
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("unsigned long", "inertia_eax", None),
    )


def test_gp_runtime_state_projects_dl_write_into_coherent_dx_parent() -> None:
    """A DL write preserves the high byte and instruction origin."""
    arch = Arch86_16()
    dl_offset, dl_size = arch.registers["dl"]
    artifact = _gp_live_in_artifact("dx")
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={artifact.function_addr: artifact},
        _inertia_function_ssa_stages_8616={artifact.function_addr: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    dl = CDirtyExpression(
        Expr.VirtualVariable(
            1,
            3,
            dl_size * 8,
            VirtualVariableCategory.REGISTER,
            oident=dl_offset,
        ),
        codegen=codegen,
    )
    value = CVariable(SimMemoryVariable(0x2000, 2, name="value"), variable_type=SimTypeShort(False), codegen=codegen)
    value.variable_type = SimTypeShort(False)
    assignment = CAssignment(
        dl,
        value,
        codegen=codegen,
        tags={"ins_addr": 0x10E90},
    )
    codegen.cfunc = SimpleNamespace(
        addr=artifact.function_addr,
        statements=assignment,
        unified_local_vars={},
    )

    assert lower_architectural_gp_register_state_8616(codegen) is True
    replacement = codegen.cfunc.statements
    assert isinstance(replacement, CAssignment)
    assert isinstance(replacement.lhs, CVariable)
    assert replacement.lhs.variable.name == "inertia_edx"
    assert isinstance(replacement.rhs, CBinaryOp)
    assert replacement.rhs.op == "Or"
    assert replacement.rhs.lhs.op == "And"
    assert replacement.rhs.lhs.rhs.value == 0xFFFFFF00
    assert replacement.rhs.rhs.op == "And"
    assert replacement.rhs.rhs.rhs.value == 0xFF
    assert replacement.tags == assignment.tags


def test_gp_runtime_state_materializes_eax_as_32bit_lane() -> None:
    """An SSA-proven EAX live-in lowers to one explicit 32-bit runtime global."""
    arch = Arch86_16()
    eax_offset, eax_size = arch.registers["eax"]
    artifact = _gp_live_in_artifact("eax")
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={artifact.function_addr: artifact},
        _inertia_function_ssa_stages_8616={artifact.function_addr: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    eax = CDirtyExpression(
        Expr.VirtualVariable(
            1,
            3,
            eax_size * 8,
            VirtualVariableCategory.REGISTER,
            oident=eax_offset,
        ),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=artifact.function_addr,
        statements=eax,
        unified_local_vars={},
    )

    assert lower_architectural_gp_register_state_8616(codegen) is True
    replacement = codegen.cfunc.statements
    assert isinstance(replacement, CVariable)
    assert replacement.variable.name == "inertia_eax"
    assert isinstance(replacement.type, SimTypeLong)
    assert replacement.type.size == 32
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("unsigned long", "inertia_eax", None),
    )


def test_gp_runtime_state_projects_entry_sp_from_coherent_esp_lane() -> None:
    """An SSA-proven entry SP is explicit runtime state, not an uninitialized local."""
    arch = Arch86_16()
    sp_offset, sp_size = arch.registers["sp"]
    artifact = _gp_live_in_artifact("sp")
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={artifact.function_addr: artifact},
        _inertia_function_ssa_stages_8616={artifact.function_addr: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    sp = CDirtyExpression(
        Expr.VirtualVariable(
            1,
            3,
            sp_size * 8,
            VirtualVariableCategory.REGISTER,
            oident=sp_offset,
        ),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=artifact.function_addr,
        statements=sp,
        unified_local_vars={},
    )

    assert lower_architectural_gp_register_state_8616(codegen) is True
    replacement = codegen.cfunc.statements
    assert isinstance(replacement, CBinaryOp)
    assert replacement.op == "And"
    assert isinstance(replacement.lhs, CVariable)
    assert replacement.lhs.variable.name == "inertia_esp"
    assert replacement.rhs.value == 0xFFFF
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("unsigned long", "inertia_esp", None),
    )


def _scoped_entry_project() -> SimpleNamespace:
    """Near-call-scoped function: no published project SSA artifact."""
    return SimpleNamespace(
        arch=Arch86_16(),
        _inertia_function_ssa_artifacts_8616={},
        _inertia_function_ssa_stages_8616={},
    )


def _entry_dirty(codegen: object, varid: int, register_name: str) -> CDirtyExpression:
    """Entry-version register read with the captured varid and offset."""
    offset, size = Arch86_16().registers[register_name]
    return CDirtyExpression(
        Expr.VirtualVariable(
            1,
            varid,
            size * 8,
            VirtualVariableCategory.REGISTER,
            oident=offset,
        ),
        codegen=codegen,
    )


def _stack_store(codegen: object, name: str, offset: int, rhs: object) -> CAssignment:
    """One byte stack store mirroring the captured push-local targets."""
    return CAssignment(
        CVariable(
            SimStackVariable(offset, 1, base="bp", name=name, region=0x1D43),
            variable_type=SimTypeChar(False),
            codegen=codegen,
        ),
        rhs,
        codegen=codegen,
    )


def _captured_1d43_prologue(codegen: object) -> CStatements:
    """The actual sub_1d43 prologue carriers from semantic-557432-017.

    push_lo/push_hi store entry BP (dirty varid 23) bytes at ins_addr 7491;
    mov_bp_sp assigns the BP carrier v6/ir_1 from entry SP (dirty varid 22).
    """
    arch = Arch86_16()
    bp_offset, bp_size = arch.registers["bp"]
    push_lo = _stack_store(
        codegen,
        "local_2",
        -2,
        CTypeCast(
            None,
            SimTypeChar(False),
            _entry_dirty(codegen, 23, "bp"),
            codegen=codegen,
        ),
    )
    push_hi = _stack_store(
        codegen,
        "local_1",
        -1,
        CBinaryOp(
            "Shr",
            _entry_dirty(codegen, 23, "bp"),
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )
    mov_bp_sp = CAssignment(
        CVariable(
            SimRegisterVariable(bp_offset, bp_size, ident="ir_1", region=0x1D43),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        CBinaryOp(
            "Sub",
            _entry_dirty(codegen, 22, "sp"),
            CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x1D44, "vex_stmt_idx": 23},
    )
    return CStatements([push_lo, push_hi, mov_bp_sp], codegen=codegen)


def _scoped_codegen(project: object, root: object) -> SimpleNamespace:
    """Codegen surface mirroring the production lowering boundary."""
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1D43,
        statements=root,
        unified_local_vars={},
        variables_in_use={},
        variable_manager=SimpleNamespace(set_variable_type=lambda _v, _t: None),
        refresh=lambda: None,
    )
    return codegen


def test_gp_live_in_c_ast_fallback_classifies_entry_dirty_carriers() -> None:
    """Scoped functions classify dirty entry BP/SP reads as live-ins."""
    project = _scoped_entry_project()
    codegen = _scoped_codegen(project, None)
    root = _captured_1d43_prologue(codegen)

    live_ins = gp_live_in_names_from_c_ast_8616(root, project)

    assert live_ins == frozenset({"ebp", "esp"})


def test_gp_runtime_state_materializes_scoped_entry_dirty_prologue() -> None:
    """Entry dirty carriers lower to emitted runtime lanes; stack writes stay."""
    project = _scoped_entry_project()
    codegen = _scoped_codegen(project, None)
    codegen.cfunc.statements = _captured_1d43_prologue(codegen)

    assert lower_architectural_gp_register_state_8616(codegen) is True
    root = codegen.cfunc.statements
    assert not [
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CDirtyExpression)
    ]
    push_lo, push_hi, mov_bp_sp = root.statements
    assert isinstance(push_lo.lhs.variable, SimStackVariable)
    assert push_lo.lhs.variable.name == "local_2"
    assert isinstance(push_hi.lhs.variable, SimStackVariable)
    assert push_hi.lhs.variable.name == "local_1"
    assert isinstance(push_hi.rhs, CBinaryOp) and push_hi.rhs.op == "Shr"
    bp_view = runtime_gp_expression_view_8616(push_hi.rhs.lhs)
    assert bp_view is not None and bp_view.register_name == "bp"
    lo_view = runtime_gp_expression_view_8616(
        push_lo.rhs.expr if isinstance(push_lo.rhs, CTypeCast) else push_lo.rhs
    )
    assert lo_view is not None and lo_view.register_name == "bp"
    assert isinstance(mov_bp_sp.lhs, CVariable)
    assert isinstance(mov_bp_sp.lhs.variable, SimMemoryVariable)
    assert mov_bp_sp.lhs.variable.name == "inertia_ebp"
    sp_carriers = [
        node
        for node in _iter_c_nodes_deep_8616(mov_bp_sp.rhs)
        if isinstance(node, CVariable)
        and runtime_gp_name_for_variable_8616(node.variable) == "esp"
    ]
    assert sp_carriers
    specs = set(codegen._inertia_global_declaration_specs_8616)
    assert ("unsigned long", "inertia_ebp", None) in specs
    assert ("unsigned long", "inertia_esp", None) in specs


def test_gp_runtime_state_refuses_entry_read_after_register_write() -> None:
    """An entry-version read after a new-BP write never reads the lane."""
    project = _scoped_entry_project()
    codegen = _scoped_codegen(project, None)
    prologue = _captured_1d43_prologue(codegen)
    reordered = CStatements(
        [prologue.statements[2], prologue.statements[1]],
        codegen=codegen,
    )
    codegen.cfunc.statements = reordered

    assert lower_architectural_gp_register_state_8616(codegen) is True
    mov_bp_sp, push_hi = codegen.cfunc.statements.statements
    assert isinstance(mov_bp_sp.lhs.variable, SimMemoryVariable)
    assert mov_bp_sp.lhs.variable.name == "inertia_ebp"
    assert isinstance(push_hi.rhs, CBinaryOp) and push_hi.rhs.op == "Shr"
    assert isinstance(push_hi.rhs.lhs, CDirtyExpression)
    assert push_hi.rhs.lhs.dirty.varid == 23
    assert runtime_gp_expression_view_8616(push_hi.rhs.lhs) is None


def test_gp_runtime_state_refuses_entry_read_after_dirty_write() -> None:
    """A different version's dirty BP write still clobbers the lane."""
    project = _scoped_entry_project()
    codegen = _scoped_codegen(project, None)
    dirty_write = CAssignment(
        _entry_dirty(codegen, 99, "bp"),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    late_read = _stack_store(
        codegen,
        "local_1",
        -1,
        CBinaryOp(
            "Shr",
            _entry_dirty(codegen, 23, "bp"),
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )
    codegen.cfunc.statements = CStatements([dirty_write, late_read], codegen=codegen)

    lower_architectural_gp_register_state_8616(codegen)
    _write, read_stmt = codegen.cfunc.statements.statements
    assert isinstance(read_stmt.rhs.lhs, CDirtyExpression)
    assert read_stmt.rhs.lhs.dirty.varid == 23


def test_gp_live_in_c_ast_fallback_defined_dirty_varid_not_live_in() -> None:
    """A dirty version defined inside the AST is not an entry live-in."""
    project = _scoped_entry_project()
    codegen = _scoped_codegen(project, None)
    root = CStatements(
        [
            CAssignment(
                _entry_dirty(codegen, 23, "bp"),
                CConstant(7, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            _stack_store(
                codegen,
                "local_1",
                -1,
                CBinaryOp(
                    "Shr",
                    _entry_dirty(codegen, 23, "bp"),
                    CConstant(8, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
            ),
        ],
        codegen=codegen,
    )

    assert "ebp" not in gp_live_in_names_from_c_ast_8616(root, project)


def test_entry_version_refusal_survives_lowering_replay() -> None:
    """A projected runtime write remains a clobber on subsequent passes."""
    codegen = _scoped_codegen(_scoped_entry_project(), None)
    prologue = _captured_1d43_prologue(codegen)
    codegen.cfunc.statements = CStatements(
        [prologue.statements[2], prologue.statements[1]], codegen=codegen,
    )
    for _ in range(2):
        lower_architectural_gp_register_state_8616(codegen)
        late_read = codegen.cfunc.statements.statements[-1].rhs.lhs
        assert isinstance(late_read, CDirtyExpression)
        assert late_read.dirty.varid == 23


def test_entry_version_after_effectful_call_is_not_current_register() -> None:
    """An opaque call cannot justify reading old AX from the runtime lane."""
    codegen = _scoped_codegen(_scoped_entry_project(), None)
    dirty = _entry_dirty(codegen, 23, "ax")
    read = _stack_store(codegen, "saved", -1, dirty)
    call = CExpressionStatement(
        CFunctionCall("opaque", None, args=[], codegen=codegen), codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([call, read], codegen=codegen)
    lower_architectural_gp_register_state_8616(codegen)
    assert read.rhs is dirty


def test_shared_entry_node_preserves_all_evaluations_after_write() -> None:
    """Early occurrence of a shared node cannot authorize its later read."""
    codegen = _scoped_codegen(_scoped_entry_project(), None)
    shared = _entry_dirty(codegen, 23, "bp")
    early = _stack_store(codegen, "early", -1, shared)
    late = _stack_store(codegen, "late", -2, shared)
    write = _captured_1d43_prologue(codegen).statements[2]
    codegen.cfunc.statements = CStatements([early, write, late], codegen=codegen)
    lower_architectural_gp_register_state_8616(codegen)
    assert early.rhs is shared
    assert late.rhs is shared


def test_defined_dirty_versions_preserve_old_value_across_register_overwrite() -> None:
    """Capture the old SSA value while preserving both architectural writes."""
    codegen = _scoped_codegen(_scoped_entry_project(), None)
    entry = _stack_store(codegen, "entry", -2, _entry_dirty(codegen, 1, "bp"))
    writes = [
        CAssignment(
            _entry_dirty(codegen, varid, "bp"),
            CConstant(value, SimTypeShort(False), codegen=codegen), codegen=codegen,
        )
        for varid, value in ((23, 5), (99, 9))
    ]
    returned = CReturn(_entry_dirty(codegen, 23, "bp"), codegen=codegen)
    codegen.cfunc.statements = CStatements([entry, *writes, returned], codegen=codegen)
    assert lower_architectural_gp_register_state_8616(codegen)
    captured = returned.retval
    assert isinstance(captured, CVariable)
    assert writes[0].lhs is captured
    assert writes[0].rhs.value == 5
    statements = codegen.cfunc.statements.statements
    assert statements[0] is entry
    assert statements[1] is writes[0]
    publication, overwrite = statements[2:4]
    assert publication.rhs.rhs.lhs is captured
    assert overwrite.rhs.rhs.lhs.value == 9
    assert statements[4] is returned
    assert not any(isinstance(node, CDirtyExpression)
                   for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements))


def test_gp_live_in_c_ast_fallback_distinct_varid_stays_live_in() -> None:
    """Another version's definition never seeds the entry-version read."""
    project = _scoped_entry_project()
    codegen = _scoped_codegen(project, None)
    root = CStatements(
        [
            CAssignment(
                _entry_dirty(codegen, 99, "bp"),
                CConstant(7, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            _stack_store(
                codegen,
                "local_1",
                -1,
                CBinaryOp(
                    "Shr",
                    _entry_dirty(codegen, 23, "bp"),
                    CConstant(8, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
            ),
        ],
        codegen=codegen,
    )

    assert "ebp" in gp_live_in_names_from_c_ast_8616(root, project)


def test_gp_live_in_c_ast_fallback_ignores_unproven_dirty_carriers() -> None:
    """Non-register, unprojectable, and non-varid dirty carriers refuse."""
    project = _scoped_entry_project()
    codegen = _scoped_codegen(project, None)
    bp_offset, bp_size = Arch86_16().registers["bp"]
    cases = (
        # Non-register-category dirty carriers are not register reads.
        CDirtyExpression(
            Expr.VirtualVariable(
                1, 23, bp_size * 8, VirtualVariableCategory.TMP, oident=bp_offset
            ),
            codegen=codegen,
        ),
        # Register offsets outside the GP view inventory are unprojectable.
        CDirtyExpression(
            Expr.VirtualVariable(
                1, 23, bp_size * 8, VirtualVariableCategory.REGISTER, oident=0x222
            ),
            codegen=codegen,
        ),
        # Legacy payloads without varid SSA identity never prove a version.
        CDirtyExpression(
            SimpleNamespace(reg=bp_offset, bits=bp_size * 8),
            codegen=codegen,
        ),
    )
    for index, dirty in enumerate(cases):
        root = _stack_store(codegen, f"local_{index}", -1 - index, dirty)
        assert gp_live_in_names_from_c_ast_8616(root, project) == frozenset()


def test_gp_runtime_state_materializes_unassigned_ax_carrier() -> None:
    """An unassigned SSA AX carrier is an architectural live-in, not a C local."""
    arch = Arch86_16()
    ax_offset, ax_size = arch.registers["ax"]
    ax = IRValue(MemSpace.REG, name="ax", offset=ax_offset, size=ax_size)
    artifact = SSAFunctionArtifact(
        function_addr=0x1AF_CF,
        blocks=(
            SSABlock(
                addr=0x1AF_CF,
                instrs=(
                    IRInstr(
                        "MOV",
                        ax,
                        (IRValue(MemSpace.CONST, const=0x200, size=ax_size),),
                        ax_size,
                        0x1B0_76,
                    ),
                ),
                bindings=(),
            ),
        ),
        predecessor_map={0x1AF_CF: ()},
    )
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={},
        _inertia_function_ssa_stages_8616={},
    )
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    carrier = CVariable(
        SimRegisterVariable(
            ax_offset,
            ax_size,
            ident="ir_37",
            region=artifact.function_addr,
        ),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=artifact.function_addr,
        statements=CReturn(carrier, codegen=codegen),
        unified_local_vars={},
    )
    assert gp_live_in_names_from_ssa_8616(artifact) == frozenset()
    assert gp_live_in_names_from_c_ast_8616(codegen.cfunc.statements, project) == frozenset(
        {"eax"}
    )
    assert lower_architectural_gp_register_state_8616(codegen) is True
    replacement = codegen.cfunc.statements.retval
    assert isinstance(replacement, CBinaryOp)
    assert replacement.op == "And"
    assert isinstance(replacement.lhs, CVariable)
    assert replacement.lhs.variable.name == "inertia_eax"
    assert replacement.rhs.value == 0xFFFF
