"""A missing C assignment must not override a proven native SSA definition."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CReturn, CVariable
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.function_ssa_registry import FunctionSSAArtifactStage8616
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.lowering.gp_register_state import lower_architectural_gp_register_state_8616


def test_native_definition_refuses_ast_inferred_livein():
    arch = Arch86_16()
    offset, size = arch.registers["ax"]
    address = 0x1000
    ax = IRValue(MemSpace.REG, name="ax", offset=offset, size=size)
    artifact = SSAFunctionArtifact(
        function_addr=address,
        blocks=(SSABlock(address, (
            IRInstr("MOV", ax, (IRValue(MemSpace.CONST, const=7, size=size),), size, address),
        ), bindings=()),),
        predecessor_map={address: ()},
    )
    project = SimpleNamespace(
        arch=arch,
        _inertia_function_ssa_artifacts_8616={address: artifact},
        _inertia_function_ssa_stages_8616={address: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(project=project, next_node_idx=lambda: 0, next_ident=lambda name: name, cstyle_null_cmp=False)
    variable = SimRegisterVariable(offset, size, ident="ir_7", region=address)
    carrier = CVariable(variable, codegen=codegen)
    root = CReturn(carrier, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=address, statements=root, unified_local_vars={variable: set()})

    assert lower_architectural_gp_register_state_8616(codegen) is False
    assert root.retval is carrier
    assert variable in codegen.cfunc.unified_local_vars
