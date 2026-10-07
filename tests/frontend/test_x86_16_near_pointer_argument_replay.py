from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.segmented_memory_lowering import (
    apply_runtime_segment_lowering_8616,
)
from capstone.x86_const import (
    X86_INS_MOV,
    X86_INS_PUSH,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_INVALID,
)


class _Codegen8616:
    """Minimal dynamic angr codegen boundary used by the integration regression."""

    def __init__(self, project: object) -> None:
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return a deterministic structured-C node identifier."""
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        """Return a deterministic structured-C node identifier."""
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        """Keep generated identifiers stable in the focused adapter."""
        return name


def _register(project: object, name: str, codegen: _Codegen8616) -> CVariable:
    """Build one architectural register variable at the angr boundary."""
    arch = project.arch  # type: ignore[attr-defined]
    register_offset, register_size = arch.registers[name]
    return CVariable(
        SimRegisterVariable(register_offset, register_size, name=name),
        codegen=codegen,
    )


def _register_operand(register: int) -> SimpleNamespace:
    """Build one decoded register operand for binary pointer evidence."""
    return SimpleNamespace(type=X86_OP_REG, size=2, reg=register)


def _memory_operand(base: int, displacement: int = 0) -> SimpleNamespace:
    """Build one decoded 16-bit memory operand for binary pointer evidence."""
    return SimpleNamespace(
        type=X86_OP_MEM,
        size=2,
        mem=SimpleNamespace(
            base=base,
            index=X86_REG_INVALID,
            scale=1,
            disp=displacement,
        ),
    )


def test_runtime_lowering_keeps_pointer_type_with_overlapping_stale_byte_arg() -> None:
    """Keep exact BP+6 pointer evidence beside an unresolved overlapping view."""
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch, _inertia_c_target="portable-flat")
    codegen = _Codegen8616(project)
    scalar_type = SimTypeShort(False).with_arch(arch)
    byte_type = SimTypeChar(False).with_arch(arch)
    argc = CVariable(
        SimStackVariable(4, 2, base="bp", name="argc", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    stale_byte = CVariable(
        SimStackVariable(5, 1, base="bp", name="local_5", region=0x4010),
        variable_type=byte_type,
        codegen=codegen,
    )
    argv = CVariable(
        SimStackVariable(6, 2, base="bp", name="argv", region=0x4010),
        variable_type=scalar_type,
        codegen=codegen,
    )
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [_register(project, "ds", codegen), argv],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U16"},
    )
    stack_helper = CFunctionCall(
        "SEG_U16",
        None,
        [_register(project, "ss", codegen), argv],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U16"},
    )
    statements = CStatements(
        [
            CExpressionStatement(argc, codegen=codegen),
            CExpressionStatement(argv, codegen=codegen),
            CExpressionStatement(helper, codegen=codegen),
            CExpressionStatement(stack_helper, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    prototype = SimTypeFunction(
        [scalar_type, byte_type, scalar_type],
        scalar_type,
        arg_names=["argc", "local_5", "argv"],
    ).with_arch(arch)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=statements,
        body=statements,
        arg_list=[argc, stale_byte, argv],
        functy=prototype,
        prototype=prototype,
        variables_in_use={
            argc.variable: argc,
            stale_byte.variable: stale_byte,
            argv.variable: argv,
        },
        unified_local_vars={},
    )
    load_argv = SimpleNamespace(
        address=0x1000,
        id=X86_INS_MOV,
        operands=(_register_operand(X86_REG_BX), _memory_operand(X86_REG_BP, 6)),
    )
    dereference_argv = SimpleNamespace(
        address=0x1003,
        id=X86_INS_PUSH,
        operands=(_memory_operand(X86_REG_BX),),
    )
    block = SimpleNamespace(
        addr=0x1000,
        capstone=SimpleNamespace(
            insns=(
                SimpleNamespace(insn=load_argv),
                SimpleNamespace(insn=dereference_argv),
            )
        ),
    )
    function = SimpleNamespace(
        prototype=prototype,
        prototype_source=PrototypeSource.GUESSED,
        is_prototype_guessed=True,
        info={},
        block_addrs_set=set(),
        blocks=(block,),
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(get=lambda _addr: function)
    )

    assert apply_runtime_segment_lowering_8616(codegen) is True

    assert codegen.cfunc.arg_list == [argc, stale_byte, argv]
    assert isinstance(argv.variable_type, SimTypePointer)
    assert isinstance(codegen.cfunc.functy.args[2], SimTypePointer)
    stats = codegen._inertia_near_pointer_argument_stats_8616
    assert stats.classified_fact_count == stats.materialized_count == 1
    assert stats.failure_count == 0
