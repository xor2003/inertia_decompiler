from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CReturn,
    CStatements,
    CVariable,
)
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.annotations import ANNOTATION_KEY
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.lowering.stack_prototype_materialization import (
    materialize_annotated_stack_prototype_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from angr_platforms.X86_16.structuring import branch_return_expressions
from angr_platforms.X86_16.structuring.branch_return_expressions import (
    branch_target_preserves_return_registers_8616,
    recover_branch_target_return_expression_8616,
    sole_return_expression_8616,
)
from archinfo import ArchX86


@dataclass
class _Operand:
    type: int
    reg: int = 0
    imm: int = 0
    size: int = 2
    mem: object | None = None


class _Insn:
    def __init__(self, mnemonic: str, operands: tuple[_Operand, ...]) -> None:
        self.mnemonic = mnemonic
        self.operands = operands

    def reg_name(self, reg_id: int) -> str:
        return {1: "ax", 2: "dx", 3: "bp"}.get(reg_id, "")


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _Factory:
    def __init__(self, insns: tuple[_Insn, ...]) -> None:
        self._block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))

    def block(self, _addr: int, *, opt_level: int = 0) -> object:
        del opt_level
        return self._block


def _project(*insns: _Insn) -> object:
    return SimpleNamespace(factory=_Factory(insns))


def _mapped_project(blocks: dict[int, tuple[_Insn, ...]]) -> object:
    """Build a project whose block factory resolves exact CFG addresses."""
    return SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda addr, *, opt_level=0: SimpleNamespace(
                capstone=SimpleNamespace(insns=blocks[addr])
            )
        )
    )


def test_sole_return_expression_accepts_one_wrapped_return() -> None:
    codegen = _Codegen()
    expression = CConstant(7, SimTypeShort(False), codegen=codegen)
    body = CStatements([CReturn(expression, codegen=codegen)], codegen=codegen)

    assert sole_return_expression_8616(body) is expression


@pytest.mark.parametrize("inverse", [False, True])
@pytest.mark.parametrize("case", ["valid", "missing", "same", "wrong", "prefix"])
def test_binary_return_arm_polarity_requires_both_complete_values(inverse, case):
    codegen = _Codegen()
    values = [CConstant(value, SimTypeShort(False), codegen=codegen) for value in (0, 1, 2)]
    true_value, false_value = (values[1], values[0]) if inverse else (values[0], values[1])
    true_body = CStatements([CReturn(true_value, codegen=codegen)], codegen=codegen)
    false_body = CStatements([CReturn(false_value, codegen=codegen)], codegen=codegen)
    recovered = {0x1010: values[0], 0x1020: values[1]}
    if case == "missing":
        recovered.pop(0x1020)
    elif case == "same":
        recovered[0x1020] = values[0]
    elif case == "wrong":
        recovered[0x1020] = values[2]
    elif case == "prefix":
        true_body.statements.insert(0, values[2])
    condition = ConditionIR("eq", 1, 0, taken_target=0x1010, fallthrough_target=0x1020)
    result = branch_return_expressions.binary_return_arm_polarity_8616(
        condition, true_body, false_body, recovered.get,
    )
    assert result is (not inverse if case == "valid" else None)


def test_branch_target_return_expression_recovers_signed_ax_immediate() -> None:
    codegen = _Codegen()
    project = _project(
        _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=0xFFFF))),
        _Insn("ret", ()),
    )

    expression = recover_branch_target_return_expression_8616(project, codegen, 0x1000)

    assert isinstance(expression, CConstant)
    assert expression.value == -1
    assert expression.type.signed is True


def test_branch_target_return_expression_refuses_value_before_conditional_branch() -> None:
    codegen = _Codegen()
    project = _project(
        _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=7))),
        _Insn("jge", (_Operand(2, imm=0x1100),)),
    )

    assert recover_branch_target_return_expression_8616(project, codegen, 0x1000) is None


def test_branch_target_preservation_follows_jump_only_path_to_epilogue() -> None:
    project = _mapped_project(
        {
            0x1000: (_Insn("jmp", (_Operand(2, imm=0x1010),)),),
            0x1010: (_Insn("leave", ()), _Insn("ret", ())),
        }
    )

    assert branch_target_preserves_return_registers_8616(project, 0x1000)


def test_branch_target_preservation_refuses_ax_write_before_epilogue() -> None:
    project = _mapped_project(
        {
            0x1000: (
                _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=7))),
                _Insn("jmp", (_Operand(2, imm=0x1010),)),
            ),
            0x1010: (_Insn("ret", ()),),
        }
    )

    assert not branch_target_preserves_return_registers_8616(project, 0x1000)


def test_branch_target_return_expression_uses_projected_machine_bp_argument() -> None:
    """Resolve BP+4 return evidence to an entry-SP+2 C argument."""
    arch = Arch86_16()
    codegen = _Codegen()
    codegen.project = SimpleNamespace(arch=arch)
    word_type = SimTypeShort(False).with_arch(arch)
    argument = CVariable(
        SimStackVariable(2, 2, base="bp", name="a", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[argument],
        variables_in_use={argument.variable: argument},
        unified_local_vars={},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=argument.variable,
        cvar=argument,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    memory = SimpleNamespace(base=3, index=0, disp=4)
    project = _project(_Insn("mov", (_Operand(1, reg=1), _Operand(3, mem=memory))), _Insn("ret", ()))

    expression = recover_branch_target_return_expression_8616(project, codegen, 0x1000)

    assert isinstance(expression, CVariable)
    assert expression.variable is argument.variable


def test_narrow_arguments_keep_word_storage_for_branch_returns() -> None:
    """Keep logical byte types distinct from physical 16-bit argument slots."""
    arch = Arch86_16()
    byte_type = SimTypeChar(False).with_arch(arch)
    word_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction(
        [byte_type, byte_type, word_type],
        word_type,
        arg_names=("a", "b", "which"),
    ).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        prototype=prototype,
        prototype_source=PrototypeSource.GUESSED,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    2: {"name": "a"},
                    4: {"name": "b"},
                    6: {"name": "which"},
                }
            }
        },
    )
    codegen = _Codegen()
    codegen.project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: function if addr == 0x1000 else None
            )
        ),
    )
    arguments = tuple(
        CVariable(
            SimStackVariable(offset, size, base="bp", name=name, region=0x1000),
            variable_type=type_,
            codegen=codegen,
        )
        for offset, size, name, type_ in (
            (2, 1, "a", byte_type),
            (4, 1, "b", byte_type),
            (6, 2, "which", word_type),
        )
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=list(arguments),
        variables_in_use={arg.variable: arg for arg in arguments},
        unified_local_vars={},
        functy=prototype,
        prototype=prototype,
        statements=CStatements([], codegen=codegen),
    )
    for argument, bp_offset in zip(arguments, (4, 6, 8), strict=True):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=argument.variable,
            cvar=argument,
            bp_offset=bp_offset,
            entry_sp_offset=argument.variable.offset,
            size=argument.variable.size,
        )

    assert materialize_annotated_stack_prototype_8616(codegen.project, codegen)
    assert [arg.variable.offset for arg in codegen.cfunc.arg_list] == [2, 4, 6]
    assert [arg.variable.size for arg in codegen.cfunc.arg_list] == [2, 2, 2]

    for expected, bp_offset in zip(arguments[:2], (4, 6), strict=True):
        memory = SimpleNamespace(base=3, index=0, disp=bp_offset)
        project = _project(_Insn("mov", (_Operand(1, reg=1), _Operand(3, mem=memory))), _Insn("ret", ()))
        expression = recover_branch_target_return_expression_8616(
            project,
            codegen,
            0x1000,
        )
        assert isinstance(expression, CVariable)
        assert expression.variable is expected.variable


def test_branch_target_return_expression_combines_adjacent_dx_ax_stack_slices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lowered_values: list[object] = []

    def _lower(value: object, _project: object, _codegen: object) -> CConstant:
        lowered_values.append(value)
        return CConstant(77, SimTypeShort(False), codegen=_codegen)

    monkeypatch.setattr(branch_return_expressions, "lower_ir_value_to_c_expr_8616", _lower)
    codegen = _Codegen()
    ax_mem = SimpleNamespace(base=3, index=0, disp=4)
    dx_mem = SimpleNamespace(base=3, index=0, disp=6)
    project = _project(
        _Insn("mov", (_Operand(1, reg=1), _Operand(3, mem=ax_mem))),
        _Insn("mov", (_Operand(1, reg=2), _Operand(3, mem=dx_mem))),
        _Insn("ret", ()),
    )

    expression = recover_branch_target_return_expression_8616(project, codegen, 0x1000)

    assert isinstance(expression, CConstant)
    assert expression.value == 77
    assert len(lowered_values) == 1
    assert lowered_values[0].offset == 4
    assert lowered_values[0].size == 4
