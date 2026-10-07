"""Tests for SSA-proven GP architectural runtime-state lowering."""

from __future__ import annotations

from types import SimpleNamespace

from angr.ailment import Expr
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.rustylib.ailment import VirtualVariableCategory
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import IRAddress, IRInstr, IRValue, MemSpace
from inertia.ir.function_ssa_registry import FunctionSSAArtifactStage8616
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.lowering.gp_register_state import (
    gp_live_in_names_from_c_ast_8616,
    gp_live_in_names_from_ssa_8616,
    lower_architectural_gp_register_state_8616,
    runtime_gp_expression_view_8616,
    runtime_gp_name_for_variable_8616,
)

from inertia.validation.tail_validation_fingerprint import _expr_fingerprint


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
